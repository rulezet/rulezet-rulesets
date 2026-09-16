rule TTP_XOR_MULT_DOSStub_932e {
  strings:
    $key_932e = { c7 46 [2] b3 5e [2] f4 5c [2] b3 4d [2] fd 41 [2] f1 4b [2] e6 40 [2] fd 0e [2] c0 }

  condition:
    any of them
}