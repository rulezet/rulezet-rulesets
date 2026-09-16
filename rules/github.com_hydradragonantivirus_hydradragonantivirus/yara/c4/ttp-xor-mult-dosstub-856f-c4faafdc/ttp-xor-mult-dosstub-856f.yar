rule TTP_XOR_MULT_DOSStub_856f {
  strings:
    $key_856f = { d1 07 [2] a5 1f [2] e2 1d [2] a5 0c [2] eb 00 [2] e7 0a [2] f0 01 [2] eb 4f [2] d6 }

  condition:
    any of them
}