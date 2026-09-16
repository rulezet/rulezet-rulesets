rule TTP_XOR_MULT_DOSStub_3113 {
  strings:
    $key_3113 = { 65 7b [2] 11 63 [2] 56 61 [2] 11 70 [2] 5f 7c [2] 53 76 [2] 44 7d [2] 5f 33 [2] 62 }

  condition:
    any of them
}