rule TTP_XOR_MULT_DOSStub_f744 {
  strings:
    $key_f744 = { a3 2c [2] d7 34 [2] 90 36 [2] d7 27 [2] 99 2b [2] 95 21 [2] 82 2a [2] 99 64 [2] a4 }

  condition:
    any of them
}