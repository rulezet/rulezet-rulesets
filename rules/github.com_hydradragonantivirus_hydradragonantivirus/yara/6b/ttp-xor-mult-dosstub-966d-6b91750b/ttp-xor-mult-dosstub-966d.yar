rule TTP_XOR_MULT_DOSStub_966d {
  strings:
    $key_966d = { c2 05 [2] b6 1d [2] f1 1f [2] b6 0e [2] f8 02 [2] f4 08 [2] e3 03 [2] f8 4d [2] c5 }

  condition:
    any of them
}