rule TTP_XOR_MULT_DOSStub_947e {
  strings:
    $key_947e = { c0 16 [2] b4 0e [2] f3 0c [2] b4 1d [2] fa 11 [2] f6 1b [2] e1 10 [2] fa 5e [2] c7 }

  condition:
    any of them
}