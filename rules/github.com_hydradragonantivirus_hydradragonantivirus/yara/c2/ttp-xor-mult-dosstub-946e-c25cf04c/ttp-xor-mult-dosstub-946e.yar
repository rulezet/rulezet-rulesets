rule TTP_XOR_MULT_DOSStub_946e {
  strings:
    $key_946e = { c0 06 [2] b4 1e [2] f3 1c [2] b4 0d [2] fa 01 [2] f6 0b [2] e1 00 [2] fa 4e [2] c7 }

  condition:
    any of them
}