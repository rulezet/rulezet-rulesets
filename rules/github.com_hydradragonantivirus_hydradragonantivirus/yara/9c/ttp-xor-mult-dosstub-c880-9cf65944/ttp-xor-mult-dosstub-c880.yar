rule TTP_XOR_MULT_DOSStub_c880 {
  strings:
    $key_c880 = { 9c e8 [2] e8 f0 [2] af f2 [2] e8 e3 [2] a6 ef [2] aa e5 [2] bd ee [2] a6 a0 [2] 9b }

  condition:
    any of them
}