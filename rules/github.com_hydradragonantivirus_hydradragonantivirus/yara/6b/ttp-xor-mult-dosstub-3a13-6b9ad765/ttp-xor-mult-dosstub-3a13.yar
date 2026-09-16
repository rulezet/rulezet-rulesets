rule TTP_XOR_MULT_DOSStub_3a13 {
  strings:
    $key_3a13 = { 6e 7b [2] 1a 63 [2] 5d 61 [2] 1a 70 [2] 54 7c [2] 58 76 [2] 4f 7d [2] 54 33 [2] 69 }

  condition:
    any of them
}