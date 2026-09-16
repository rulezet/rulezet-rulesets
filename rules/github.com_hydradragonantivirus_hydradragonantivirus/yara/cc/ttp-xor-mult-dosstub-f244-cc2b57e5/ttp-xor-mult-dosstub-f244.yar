rule TTP_XOR_MULT_DOSStub_f244 {
  strings:
    $key_f244 = { a6 2c [2] d2 34 [2] 95 36 [2] d2 27 [2] 9c 2b [2] 90 21 [2] 87 2a [2] 9c 64 [2] a1 }

  condition:
    any of them
}