rule TTP_XOR_MULT_DOSStub_960d {
  strings:
    $key_960d = { c2 65 [2] b6 7d [2] f1 7f [2] b6 6e [2] f8 62 [2] f4 68 [2] e3 63 [2] f8 2d [2] c5 }

  condition:
    any of them
}