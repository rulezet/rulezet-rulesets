rule TTP_XOR_MULT_DOSStub_1dd9 {
  strings:
    $key_1dd9 = { 49 b1 [2] 3d a9 [2] 7a ab [2] 3d ba [2] 73 b6 [2] 7f bc [2] 68 b7 [2] 73 f9 [2] 4e }

  condition:
    any of them
}