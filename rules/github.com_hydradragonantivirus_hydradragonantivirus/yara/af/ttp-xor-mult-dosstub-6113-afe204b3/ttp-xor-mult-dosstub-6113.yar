rule TTP_XOR_MULT_DOSStub_6113 {
  strings:
    $key_6113 = { 35 7b [2] 41 63 [2] 06 61 [2] 41 70 [2] 0f 7c [2] 03 76 [2] 14 7d [2] 0f 33 [2] 32 }

  condition:
    any of them
}