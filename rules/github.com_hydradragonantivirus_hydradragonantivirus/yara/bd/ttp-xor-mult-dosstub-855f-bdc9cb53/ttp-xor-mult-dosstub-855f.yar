rule TTP_XOR_MULT_DOSStub_855f {
  strings:
    $key_855f = { d1 37 [2] a5 2f [2] e2 2d [2] a5 3c [2] eb 30 [2] e7 3a [2] f0 31 [2] eb 7f [2] d6 }

  condition:
    any of them
}