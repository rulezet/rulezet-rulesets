rule TTP_XOR_MULT_DOSStub_4dd9 {
  strings:
    $key_4dd9 = { 19 b1 [2] 6d a9 [2] 2a ab [2] 6d ba [2] 23 b6 [2] 2f bc [2] 38 b7 [2] 23 f9 [2] 1e }

  condition:
    any of them
}