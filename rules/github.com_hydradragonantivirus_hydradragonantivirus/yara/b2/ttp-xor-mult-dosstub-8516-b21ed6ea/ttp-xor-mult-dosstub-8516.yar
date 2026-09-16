rule TTP_XOR_MULT_DOSStub_8516 {
  strings:
    $key_8516 = { d1 7e [2] a5 66 [2] e2 64 [2] a5 75 [2] eb 79 [2] e7 73 [2] f0 78 [2] eb 36 [2] d6 }

  condition:
    any of them
}