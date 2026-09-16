rule TTP_XOR_MULT_DOSStub_3dd9 {
  strings:
    $key_3dd9 = { 69 b1 [2] 1d a9 [2] 5a ab [2] 1d ba [2] 53 b6 [2] 5f bc [2] 48 b7 [2] 53 f9 [2] 6e }

  condition:
    any of them
}