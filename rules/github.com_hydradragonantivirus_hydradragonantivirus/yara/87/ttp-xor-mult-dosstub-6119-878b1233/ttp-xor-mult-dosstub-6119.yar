rule TTP_XOR_MULT_DOSStub_6119 {
  strings:
    $key_6119 = { 35 71 [2] 41 69 [2] 06 6b [2] 41 7a [2] 0f 76 [2] 03 7c [2] 14 77 [2] 0f 39 [2] 32 }

  condition:
    any of them
}