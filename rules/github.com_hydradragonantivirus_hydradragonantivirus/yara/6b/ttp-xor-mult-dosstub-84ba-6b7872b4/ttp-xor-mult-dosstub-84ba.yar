rule TTP_XOR_MULT_DOSStub_84ba {
  strings:
    $key_84ba = { d0 d2 [2] a4 ca [2] e3 c8 [2] a4 d9 [2] ea d5 [2] e6 df [2] f1 d4 [2] ea 9a [2] d7 }

  condition:
    any of them
}