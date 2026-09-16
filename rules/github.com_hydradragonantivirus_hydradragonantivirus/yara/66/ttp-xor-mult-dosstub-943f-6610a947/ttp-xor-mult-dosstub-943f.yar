rule TTP_XOR_MULT_DOSStub_943f {
  strings:
    $key_943f = { c0 57 [2] b4 4f [2] f3 4d [2] b4 5c [2] fa 50 [2] f6 5a [2] e1 51 [2] fa 1f [2] c7 }

  condition:
    any of them
}