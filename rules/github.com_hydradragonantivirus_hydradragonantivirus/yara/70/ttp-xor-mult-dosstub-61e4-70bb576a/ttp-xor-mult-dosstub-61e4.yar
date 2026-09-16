rule TTP_XOR_MULT_DOSStub_61e4 {
  strings:
    $key_61e4 = { 35 8c [2] 41 94 [2] 06 96 [2] 41 87 [2] 0f 8b [2] 03 81 [2] 14 8a [2] 0f c4 [2] 32 }

  condition:
    any of them
}