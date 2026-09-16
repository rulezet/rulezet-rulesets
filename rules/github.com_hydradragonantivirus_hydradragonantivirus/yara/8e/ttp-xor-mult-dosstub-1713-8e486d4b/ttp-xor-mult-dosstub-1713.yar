rule TTP_XOR_MULT_DOSStub_1713 {
  strings:
    $key_1713 = { 43 7b [2] 37 63 [2] 70 61 [2] 37 70 [2] 79 7c [2] 75 76 [2] 62 7d [2] 79 33 [2] 44 }

  condition:
    any of them
}