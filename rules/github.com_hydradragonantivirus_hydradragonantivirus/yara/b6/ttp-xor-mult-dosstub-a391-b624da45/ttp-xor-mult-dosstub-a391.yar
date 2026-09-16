rule TTP_XOR_MULT_DOSStub_a391 {
  strings:
    $key_a391 = { f7 f9 [2] 83 e1 [2] c4 e3 [2] 83 f2 [2] cd fe [2] c1 f4 [2] d6 ff [2] cd b1 [2] f0 }

  condition:
    any of them
}