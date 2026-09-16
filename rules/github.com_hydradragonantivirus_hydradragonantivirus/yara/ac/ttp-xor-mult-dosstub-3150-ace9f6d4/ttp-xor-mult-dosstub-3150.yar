rule TTP_XOR_MULT_DOSStub_3150 {
  strings:
    $key_3150 = { 65 38 [2] 11 20 [2] 56 22 [2] 11 33 [2] 5f 3f [2] 53 35 [2] 44 3e [2] 5f 70 [2] 62 }

  condition:
    any of them
}