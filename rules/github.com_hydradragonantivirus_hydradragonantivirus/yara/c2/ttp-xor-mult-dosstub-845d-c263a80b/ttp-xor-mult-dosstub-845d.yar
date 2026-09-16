rule TTP_XOR_MULT_DOSStub_845d {
  strings:
    $key_845d = { d0 35 [2] a4 2d [2] e3 2f [2] a4 3e [2] ea 32 [2] e6 38 [2] f1 33 [2] ea 7d [2] d7 }

  condition:
    any of them
}