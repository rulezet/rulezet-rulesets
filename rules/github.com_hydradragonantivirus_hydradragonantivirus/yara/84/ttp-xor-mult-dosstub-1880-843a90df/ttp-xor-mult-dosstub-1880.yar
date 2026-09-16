rule TTP_XOR_MULT_DOSStub_1880 {
  strings:
    $key_1880 = { 4c e8 [2] 38 f0 [2] 7f f2 [2] 38 e3 [2] 76 ef [2] 7a e5 [2] 6d ee [2] 76 a0 [2] 4b }

  condition:
    any of them
}