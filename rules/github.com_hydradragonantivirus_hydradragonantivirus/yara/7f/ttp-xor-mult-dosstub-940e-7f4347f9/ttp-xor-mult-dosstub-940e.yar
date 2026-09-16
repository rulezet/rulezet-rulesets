rule TTP_XOR_MULT_DOSStub_940e {
  strings:
    $key_940e = { c0 66 [2] b4 7e [2] f3 7c [2] b4 6d [2] fa 61 [2] f6 6b [2] e1 60 [2] fa 2e [2] c7 }

  condition:
    any of them
}