rule TTP_XOR_MULT_DOSStub_dc81 {
  strings:
    $key_dc81 = { 88 e9 [2] fc f1 [2] bb f3 [2] fc e2 [2] b2 ee [2] be e4 [2] a9 ef [2] b2 a1 [2] 8f }

  condition:
    any of them
}