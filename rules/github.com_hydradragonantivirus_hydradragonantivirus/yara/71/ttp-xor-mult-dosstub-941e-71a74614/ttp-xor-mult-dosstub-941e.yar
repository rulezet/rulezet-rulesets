rule TTP_XOR_MULT_DOSStub_941e {
  strings:
    $key_941e = { c0 76 [2] b4 6e [2] f3 6c [2] b4 7d [2] fa 71 [2] f6 7b [2] e1 70 [2] fa 3e [2] c7 }

  condition:
    any of them
}