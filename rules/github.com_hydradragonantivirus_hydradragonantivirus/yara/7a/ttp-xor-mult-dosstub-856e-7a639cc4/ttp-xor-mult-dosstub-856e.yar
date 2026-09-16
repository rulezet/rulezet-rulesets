rule TTP_XOR_MULT_DOSStub_856e {
  strings:
    $key_856e = { d1 06 [2] a5 1e [2] e2 1c [2] a5 0d [2] eb 01 [2] e7 0b [2] f0 00 [2] eb 4e [2] d6 }

  condition:
    any of them
}