rule TTP_XOR_MULT_DOSStub_61e9 {
  strings:
    $key_61e9 = { 35 81 [2] 41 99 [2] 06 9b [2] 41 8a [2] 0f 86 [2] 03 8c [2] 14 87 [2] 0f c9 [2] 32 }

  condition:
    any of them
}