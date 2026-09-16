rule TTP_XOR_MULT_DOSStub_3102 {
  strings:
    $key_3102 = { 65 6a [2] 11 72 [2] 56 70 [2] 11 61 [2] 5f 6d [2] 53 67 [2] 44 6c [2] 5f 22 [2] 62 }

  condition:
    any of them
}