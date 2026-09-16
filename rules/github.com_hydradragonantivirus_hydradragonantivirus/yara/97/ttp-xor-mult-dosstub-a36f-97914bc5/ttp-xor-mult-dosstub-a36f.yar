rule TTP_XOR_MULT_DOSStub_a36f {
  strings:
    $key_a36f = { f7 07 [2] 83 1f [2] c4 1d [2] 83 0c [2] cd 00 [2] c1 0a [2] d6 01 [2] cd 4f [2] f0 }

  condition:
    any of them
}