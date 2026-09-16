rule TTP_XOR_MULT_DOSStub_6153 {
  strings:
    $key_6153 = { 35 3b [2] 41 23 [2] 06 21 [2] 41 30 [2] 0f 3c [2] 03 36 [2] 14 3d [2] 0f 73 [2] 32 }

  condition:
    any of them
}