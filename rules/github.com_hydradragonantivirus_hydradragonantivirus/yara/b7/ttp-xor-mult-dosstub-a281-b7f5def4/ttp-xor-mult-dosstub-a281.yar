rule TTP_XOR_MULT_DOSStub_a281 {
  strings:
    $key_a281 = { f6 e9 [2] 82 f1 [2] c5 f3 [2] 82 e2 [2] cc ee [2] c0 e4 [2] d7 ef [2] cc a1 [2] f1 }

  condition:
    any of them
}