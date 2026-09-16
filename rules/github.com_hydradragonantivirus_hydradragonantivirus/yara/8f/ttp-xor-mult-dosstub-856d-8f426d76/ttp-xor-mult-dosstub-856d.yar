rule TTP_XOR_MULT_DOSStub_856d {
  strings:
    $key_856d = { d1 05 [2] a5 1d [2] e2 1f [2] a5 0e [2] eb 02 [2] e7 08 [2] f0 03 [2] eb 4d [2] d6 }

  condition:
    any of them
}