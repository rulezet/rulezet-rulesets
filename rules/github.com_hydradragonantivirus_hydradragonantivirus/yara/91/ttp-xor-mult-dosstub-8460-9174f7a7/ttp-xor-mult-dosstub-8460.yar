rule TTP_XOR_MULT_DOSStub_8460 {
  strings:
    $key_8460 = { d0 08 [2] a4 10 [2] e3 12 [2] a4 03 [2] ea 0f [2] e6 05 [2] f1 0e [2] ea 40 [2] d7 }

  condition:
    any of them
}