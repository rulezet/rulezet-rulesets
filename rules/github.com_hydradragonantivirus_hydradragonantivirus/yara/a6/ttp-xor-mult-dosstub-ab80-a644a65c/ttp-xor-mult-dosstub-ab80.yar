rule TTP_XOR_MULT_DOSStub_ab80 {
  strings:
    $key_ab80 = { ff e8 [2] 8b f0 [2] cc f2 [2] 8b e3 [2] c5 ef [2] c9 e5 [2] de ee [2] c5 a0 [2] f8 }

  condition:
    any of them
}