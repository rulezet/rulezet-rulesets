rule TTP_XOR_MULT_DOSStub_45e4 {
  strings:
    $key_45e4 = { 11 8c [2] 65 94 [2] 22 96 [2] 65 87 [2] 2b 8b [2] 27 81 [2] 30 8a [2] 2b c4 [2] 16 }

  condition:
    any of them
}