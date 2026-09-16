rule TTP_XOR_MULT_DOSStub_841d {
  strings:
    $key_841d = { d0 75 [2] a4 6d [2] e3 6f [2] a4 7e [2] ea 72 [2] e6 78 [2] f1 73 [2] ea 3d [2] d7 }

  condition:
    any of them
}