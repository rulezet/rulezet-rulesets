rule TTP_XOR_MULT_DOSStub_937d {
  strings:
    $key_937d = { c7 15 [2] b3 0d [2] f4 0f [2] b3 1e [2] fd 12 [2] f1 18 [2] e6 13 [2] fd 5d [2] c0 }

  condition:
    any of them
}