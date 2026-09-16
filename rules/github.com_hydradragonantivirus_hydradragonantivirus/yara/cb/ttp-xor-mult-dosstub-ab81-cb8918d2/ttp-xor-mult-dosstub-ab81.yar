rule TTP_XOR_MULT_DOSStub_ab81 {
  strings:
    $key_ab81 = { ff e9 [2] 8b f1 [2] cc f3 [2] 8b e2 [2] c5 ee [2] c9 e4 [2] de ef [2] c5 a1 [2] f8 }

  condition:
    any of them
}