rule TTP_XOR_MULT_DOSStub_a36d {
  strings:
    $key_a36d = { f7 05 [2] 83 1d [2] c4 1f [2] 83 0e [2] cd 02 [2] c1 08 [2] d6 03 [2] cd 4d [2] f0 }

  condition:
    any of them
}