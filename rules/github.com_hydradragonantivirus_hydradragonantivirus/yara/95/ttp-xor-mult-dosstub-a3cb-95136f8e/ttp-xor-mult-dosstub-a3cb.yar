rule TTP_XOR_MULT_DOSStub_a3cb {
  strings:
    $key_a3cb = { f7 a3 [2] 83 bb [2] c4 b9 [2] 83 a8 [2] cd a4 [2] c1 ae [2] d6 a5 [2] cd eb [2] f0 }

  condition:
    any of them
}