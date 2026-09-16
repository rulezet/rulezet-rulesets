rule TTP_XOR_MULT_DOSStub_937e {
  strings:
    $key_937e = { c7 16 [2] b3 0e [2] f4 0c [2] b3 1d [2] fd 11 [2] f1 1b [2] e6 10 [2] fd 5e [2] c0 }

  condition:
    any of them
}