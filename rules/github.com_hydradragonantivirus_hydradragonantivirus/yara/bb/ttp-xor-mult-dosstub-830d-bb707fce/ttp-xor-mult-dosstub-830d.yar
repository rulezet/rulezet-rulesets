rule TTP_XOR_MULT_DOSStub_830d {
  strings:
    $key_830d = { d7 65 [2] a3 7d [2] e4 7f [2] a3 6e [2] ed 62 [2] e1 68 [2] f6 63 [2] ed 2d [2] d0 }

  condition:
    any of them
}