rule TTP_XOR_MULT_DOSStub_a32f {
  strings:
    $key_a32f = { f7 47 [2] 83 5f [2] c4 5d [2] 83 4c [2] cd 40 [2] c1 4a [2] d6 41 [2] cd 0f [2] f0 }

  condition:
    any of them
}