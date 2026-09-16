rule TTP_XOR_MULT_DOSStub_851f {
  strings:
    $key_851f = { d1 77 [2] a5 6f [2] e2 6d [2] a5 7c [2] eb 70 [2] e7 7a [2] f0 71 [2] eb 3f [2] d6 }

  condition:
    any of them
}