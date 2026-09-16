rule TTP_XOR_MULT_DOSStub_5dd9 {
  strings:
    $key_5dd9 = { 09 b1 [2] 7d a9 [2] 3a ab [2] 7d ba [2] 33 b6 [2] 3f bc [2] 28 b7 [2] 33 f9 [2] 0e }

  condition:
    any of them
}