rule TTP_XOR_MULT_DOSStub_3153 {
  strings:
    $key_3153 = { 65 3b [2] 11 23 [2] 56 21 [2] 11 30 [2] 5f 3c [2] 53 36 [2] 44 3d [2] 5f 73 [2] 62 }

  condition:
    any of them
}