rule TTP_XOR_MULT_DOSStub_f779 {
  strings:
    $key_f779 = { a3 11 [2] d7 09 [2] 90 0b [2] d7 1a [2] 99 16 [2] 95 1c [2] 82 17 [2] 99 59 [2] a4 }

  condition:
    any of them
}