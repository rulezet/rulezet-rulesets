rule TTP_XOR_MULT_DOSStub_1d97 {
  strings:
    $key_1d97 = { 49 ff [2] 3d e7 [2] 7a e5 [2] 3d f4 [2] 73 f8 [2] 7f f2 [2] 68 f9 [2] 73 b7 [2] 4e }

  condition:
    any of them
}