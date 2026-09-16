rule TTP_XOR_MULT_DOSStub_6108 {
  strings:
    $key_6108 = { 35 60 [2] 41 78 [2] 06 7a [2] 41 6b [2] 0f 67 [2] 03 6d [2] 14 66 [2] 0f 28 [2] 32 }

  condition:
    any of them
}