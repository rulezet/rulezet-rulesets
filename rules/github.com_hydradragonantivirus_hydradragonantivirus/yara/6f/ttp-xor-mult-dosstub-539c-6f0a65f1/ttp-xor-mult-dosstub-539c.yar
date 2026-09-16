rule TTP_XOR_MULT_DOSStub_539c {
  strings:
    $key_539c = { 07 f4 [2] 73 ec [2] 34 ee [2] 73 ff [2] 3d f3 [2] 31 f9 [2] 26 f2 [2] 3d bc [2] 00 }

  condition:
    any of them
}