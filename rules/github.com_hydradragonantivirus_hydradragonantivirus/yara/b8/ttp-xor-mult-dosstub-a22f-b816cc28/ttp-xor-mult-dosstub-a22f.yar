rule TTP_XOR_MULT_DOSStub_a22f {
  strings:
    $key_a22f = { f6 47 [2] 82 5f [2] c5 5d [2] 82 4c [2] cc 40 [2] c0 4a [2] d7 41 [2] cc 0f [2] f1 }

  condition:
    any of them
}