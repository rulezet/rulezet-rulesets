rule TTP_XOR_MULT_DOSStub_538b {
  strings:
    $key_538b = { 07 e3 [2] 73 fb [2] 34 f9 [2] 73 e8 [2] 3d e4 [2] 31 ee [2] 26 e5 [2] 3d ab [2] 00 }

  condition:
    any of them
}