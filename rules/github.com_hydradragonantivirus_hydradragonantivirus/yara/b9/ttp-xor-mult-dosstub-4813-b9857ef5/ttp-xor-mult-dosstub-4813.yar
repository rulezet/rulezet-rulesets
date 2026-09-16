rule TTP_XOR_MULT_DOSStub_4813 {
  strings:
    $key_4813 = { 1c 7b [2] 68 63 [2] 2f 61 [2] 68 70 [2] 26 7c [2] 2a 76 [2] 3d 7d [2] 26 33 [2] 1b }

  condition:
    any of them
}