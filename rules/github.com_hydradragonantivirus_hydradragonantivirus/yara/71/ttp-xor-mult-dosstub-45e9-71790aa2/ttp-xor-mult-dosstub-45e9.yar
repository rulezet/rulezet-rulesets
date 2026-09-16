rule TTP_XOR_MULT_DOSStub_45e9 {
  strings:
    $key_45e9 = { 11 81 [2] 65 99 [2] 22 9b [2] 65 8a [2] 2b 86 [2] 27 8c [2] 30 87 [2] 2b c9 [2] 16 }

  condition:
    any of them
}