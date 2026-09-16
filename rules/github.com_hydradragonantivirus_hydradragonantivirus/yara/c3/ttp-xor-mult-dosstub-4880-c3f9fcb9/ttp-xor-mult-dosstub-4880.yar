rule TTP_XOR_MULT_DOSStub_4880 {
  strings:
    $key_4880 = { 1c e8 [2] 68 f0 [2] 2f f2 [2] 68 e3 [2] 26 ef [2] 2a e5 [2] 3d ee [2] 26 a0 [2] 1b }

  condition:
    any of them
}