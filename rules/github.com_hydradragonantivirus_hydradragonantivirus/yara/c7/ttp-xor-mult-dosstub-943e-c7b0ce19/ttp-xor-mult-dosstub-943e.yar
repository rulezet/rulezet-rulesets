rule TTP_XOR_MULT_DOSStub_943e {
  strings:
    $key_943e = { c0 56 [2] b4 4e [2] f3 4c [2] b4 5d [2] fa 51 [2] f6 5b [2] e1 50 [2] fa 1e [2] c7 }

  condition:
    any of them
}