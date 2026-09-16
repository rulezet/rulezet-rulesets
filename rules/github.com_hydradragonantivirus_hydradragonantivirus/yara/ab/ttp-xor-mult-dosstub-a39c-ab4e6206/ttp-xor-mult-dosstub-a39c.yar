rule TTP_XOR_MULT_DOSStub_a39c {
  strings:
    $key_a39c = { f7 f4 [2] 83 ec [2] c4 ee [2] 83 ff [2] cd f3 [2] c1 f9 [2] d6 f2 [2] cd bc [2] f0 }

  condition:
    any of them
}