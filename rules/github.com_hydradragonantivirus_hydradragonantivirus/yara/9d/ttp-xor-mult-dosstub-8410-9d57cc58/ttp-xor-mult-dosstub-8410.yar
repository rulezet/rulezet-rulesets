rule TTP_XOR_MULT_DOSStub_8410 {
  strings:
    $key_8410 = { d0 78 [2] a4 60 [2] e3 62 [2] a4 73 [2] ea 7f [2] e6 75 [2] f1 7e [2] ea 30 [2] d7 }

  condition:
    any of them
}