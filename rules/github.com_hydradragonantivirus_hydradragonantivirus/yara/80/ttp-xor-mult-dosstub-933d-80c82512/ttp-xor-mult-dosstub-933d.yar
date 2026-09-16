rule TTP_XOR_MULT_DOSStub_933d {
  strings:
    $key_933d = { c7 55 [2] b3 4d [2] f4 4f [2] b3 5e [2] fd 52 [2] f1 58 [2] e6 53 [2] fd 1d [2] c0 }

  condition:
    any of them
}