rule TTP_XOR_MULT_DOSStub_913e {
  strings:
    $key_913e = { c5 56 [2] b1 4e [2] f6 4c [2] b1 5d [2] ff 51 [2] f3 5b [2] e4 50 [2] ff 1e [2] c2 }

  condition:
    any of them
}