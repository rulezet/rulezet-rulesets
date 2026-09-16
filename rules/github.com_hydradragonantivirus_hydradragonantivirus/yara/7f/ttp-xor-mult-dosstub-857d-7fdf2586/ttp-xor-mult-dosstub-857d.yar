rule TTP_XOR_MULT_DOSStub_857d {
  strings:
    $key_857d = { d1 15 [2] a5 0d [2] e2 0f [2] a5 1e [2] eb 12 [2] e7 18 [2] f0 13 [2] eb 5d [2] d6 }

  condition:
    any of them
}