rule TTP_XOR_MULT_DOSStub_45f5 {
  strings:
    $key_45f5 = { 11 9d [2] 65 85 [2] 22 87 [2] 65 96 [2] 2b 9a [2] 27 90 [2] 30 9b [2] 2b d5 [2] 16 }

  condition:
    any of them
}