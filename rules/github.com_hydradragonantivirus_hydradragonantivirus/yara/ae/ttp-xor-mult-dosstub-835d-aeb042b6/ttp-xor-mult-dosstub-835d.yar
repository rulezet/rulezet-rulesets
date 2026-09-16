rule TTP_XOR_MULT_DOSStub_835d {
  strings:
    $key_835d = { d7 35 [2] a3 2d [2] e4 2f [2] a3 3e [2] ed 32 [2] e1 38 [2] f6 33 [2] ed 7d [2] d0 }

  condition:
    any of them
}