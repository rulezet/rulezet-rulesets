rule TTP_XOR_MULT_DOSStub_c980 {
  strings:
    $key_c980 = { 9d e8 [2] e9 f0 [2] ae f2 [2] e9 e3 [2] a7 ef [2] ab e5 [2] bc ee [2] a7 a0 [2] 9a }

  condition:
    any of them
}