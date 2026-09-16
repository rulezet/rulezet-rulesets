rule TTP_XOR_MULT_DOSStub_a30f {
  strings:
    $key_a30f = { f7 67 [2] 83 7f [2] c4 7d [2] 83 6c [2] cd 60 [2] c1 6a [2] d6 61 [2] cd 2f [2] f0 }

  condition:
    any of them
}