rule TTP_XOR_MULT_DOSStub_a305 {
  strings:
    $key_a305 = { f7 6d [2] 83 75 [2] c4 77 [2] 83 66 [2] cd 6a [2] c1 60 [2] d6 6b [2] cd 25 [2] f0 }

  condition:
    any of them
}