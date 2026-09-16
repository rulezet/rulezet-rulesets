rule TTP_XOR_MULT_DOSStub_843d {
  strings:
    $key_843d = { d0 55 [2] a4 4d [2] e3 4f [2] a4 5e [2] ea 52 [2] e6 58 [2] f1 53 [2] ea 1d [2] d7 }

  condition:
    any of them
}