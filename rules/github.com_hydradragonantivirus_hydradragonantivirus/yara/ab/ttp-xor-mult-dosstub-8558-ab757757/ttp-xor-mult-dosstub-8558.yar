rule TTP_XOR_MULT_DOSStub_8558 {
  strings:
    $key_8558 = { d1 30 [2] a5 28 [2] e2 2a [2] a5 3b [2] eb 37 [2] e7 3d [2] f0 36 [2] eb 78 [2] d6 }

  condition:
    any of them
}