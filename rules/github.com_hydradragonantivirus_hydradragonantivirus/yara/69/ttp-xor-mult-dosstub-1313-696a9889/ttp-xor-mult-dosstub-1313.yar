rule TTP_XOR_MULT_DOSStub_1313 {
  strings:
    $key_1313 = { 47 7b [2] 33 63 [2] 74 61 [2] 33 70 [2] 7d 7c [2] 71 76 [2] 66 7d [2] 7d 33 [2] 40 }

  condition:
    any of them
}