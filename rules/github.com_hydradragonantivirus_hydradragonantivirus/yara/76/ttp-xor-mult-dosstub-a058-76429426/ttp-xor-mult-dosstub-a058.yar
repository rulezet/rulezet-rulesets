rule TTP_XOR_MULT_DOSStub_a058 {
  strings:
    $key_a058 = { f4 30 [2] 80 28 [2] c7 2a [2] 80 3b [2] ce 37 [2] c2 3d [2] d5 36 [2] ce 78 [2] f3 }

  condition:
    any of them
}