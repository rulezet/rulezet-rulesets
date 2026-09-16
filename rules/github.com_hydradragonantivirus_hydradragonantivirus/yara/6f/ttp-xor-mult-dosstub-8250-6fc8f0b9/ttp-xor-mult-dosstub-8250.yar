rule TTP_XOR_MULT_DOSStub_8250 {
  strings:
    $key_8250 = { d6 38 [2] a2 20 [2] e5 22 [2] a2 33 [2] ec 3f [2] e0 35 [2] f7 3e [2] ec 70 [2] d1 }

  condition:
    any of them
}