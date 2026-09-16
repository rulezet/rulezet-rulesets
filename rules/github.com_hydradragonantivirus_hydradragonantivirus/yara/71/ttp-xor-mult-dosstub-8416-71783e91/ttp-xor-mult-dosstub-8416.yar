rule TTP_XOR_MULT_DOSStub_8416 {
  strings:
    $key_8416 = { d0 7e [2] a4 66 [2] e3 64 [2] a4 75 [2] ea 79 [2] e6 73 [2] f1 78 [2] ea 36 [2] d7 }

  condition:
    any of them
}