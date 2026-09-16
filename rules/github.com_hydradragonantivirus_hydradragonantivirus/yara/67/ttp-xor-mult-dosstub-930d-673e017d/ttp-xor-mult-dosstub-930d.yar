rule TTP_XOR_MULT_DOSStub_930d {
  strings:
    $key_930d = { c7 65 [2] b3 7d [2] f4 7f [2] b3 6e [2] fd 62 [2] f1 68 [2] e6 63 [2] fd 2d [2] c0 }

  condition:
    any of them
}