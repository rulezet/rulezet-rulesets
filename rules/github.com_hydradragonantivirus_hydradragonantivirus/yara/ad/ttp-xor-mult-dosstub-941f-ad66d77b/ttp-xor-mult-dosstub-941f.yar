rule TTP_XOR_MULT_DOSStub_941f {
  strings:
    $key_941f = { c0 77 [2] b4 6f [2] f3 6d [2] b4 7c [2] fa 70 [2] f6 7a [2] e1 71 [2] fa 3f [2] c7 }

  condition:
    any of them
}