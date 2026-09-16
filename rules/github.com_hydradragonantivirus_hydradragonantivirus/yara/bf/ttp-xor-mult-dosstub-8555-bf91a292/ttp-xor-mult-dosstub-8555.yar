rule TTP_XOR_MULT_DOSStub_8555 {
  strings:
    $key_8555 = { d1 3d [2] a5 25 [2] e2 27 [2] a5 36 [2] eb 3a [2] e7 30 [2] f0 3b [2] eb 75 [2] d6 }

  condition:
    any of them
}