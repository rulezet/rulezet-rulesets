rule TTP_XOR_MULT_DOSStub_a39d {
  strings:
    $key_a39d = { f7 f5 [2] 83 ed [2] c4 ef [2] 83 fe [2] cd f2 [2] c1 f8 [2] d6 f3 [2] cd bd [2] f0 }

  condition:
    any of them
}