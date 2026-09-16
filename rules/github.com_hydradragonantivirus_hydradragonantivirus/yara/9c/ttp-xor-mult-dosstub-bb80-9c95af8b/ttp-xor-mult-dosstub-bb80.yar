rule TTP_XOR_MULT_DOSStub_bb80 {
  strings:
    $key_bb80 = { ef e8 [2] 9b f0 [2] dc f2 [2] 9b e3 [2] d5 ef [2] d9 e5 [2] ce ee [2] d5 a0 [2] e8 }

  condition:
    any of them
}