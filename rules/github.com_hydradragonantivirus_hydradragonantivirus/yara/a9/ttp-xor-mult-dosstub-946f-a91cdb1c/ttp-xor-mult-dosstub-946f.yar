rule TTP_XOR_MULT_DOSStub_946f {
  strings:
    $key_946f = { c0 07 [2] b4 1f [2] f3 1d [2] b4 0c [2] fa 00 [2] f6 0a [2] e1 01 [2] fa 4f [2] c7 }

  condition:
    any of them
}