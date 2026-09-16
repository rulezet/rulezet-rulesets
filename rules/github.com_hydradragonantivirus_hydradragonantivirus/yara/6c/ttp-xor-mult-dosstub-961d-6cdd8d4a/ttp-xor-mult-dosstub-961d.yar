rule TTP_XOR_MULT_DOSStub_961d {
  strings:
    $key_961d = { c2 75 [2] b6 6d [2] f1 6f [2] b6 7e [2] f8 72 [2] f4 78 [2] e3 73 [2] f8 3d [2] c5 }

  condition:
    any of them
}