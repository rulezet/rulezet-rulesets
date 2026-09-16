rule TTP_XOR_MULT_DOSStub_8787 {
  strings:
    $key_8787 = { d3 ef [2] a7 f7 [2] e0 f5 [2] a7 e4 [2] e9 e8 [2] e5 e2 [2] f2 e9 [2] e9 a7 [2] d4 }

  condition:
    any of them
}