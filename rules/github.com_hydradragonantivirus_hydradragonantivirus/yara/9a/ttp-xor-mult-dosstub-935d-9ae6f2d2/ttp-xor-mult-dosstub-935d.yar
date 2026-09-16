rule TTP_XOR_MULT_DOSStub_935d {
  strings:
    $key_935d = { c7 35 [2] b3 2d [2] f4 2f [2] b3 3e [2] fd 32 [2] f1 38 [2] e6 33 [2] fd 7d [2] c0 }

  condition:
    any of them
}