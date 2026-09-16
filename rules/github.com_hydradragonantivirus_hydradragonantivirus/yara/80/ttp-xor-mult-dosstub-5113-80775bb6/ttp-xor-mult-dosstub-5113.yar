rule TTP_XOR_MULT_DOSStub_5113 {
  strings:
    $key_5113 = { 05 7b [2] 71 63 [2] 36 61 [2] 71 70 [2] 3f 7c [2] 33 76 [2] 24 7d [2] 3f 33 [2] 02 }

  condition:
    any of them
}