rule TTP_XOR_MULT_DOSStub_941c {
  strings:
    $key_941c = { c0 74 [2] b4 6c [2] f3 6e [2] b4 7f [2] fa 73 [2] f6 79 [2] e1 72 [2] fa 3c [2] c7 }

  condition:
    any of them
}