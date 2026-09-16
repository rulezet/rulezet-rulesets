rule TTP_XOR_MULT_DOSStub_942f {
  strings:
    $key_942f = { c0 47 [2] b4 5f [2] f3 5d [2] b4 4c [2] fa 40 [2] f6 4a [2] e1 41 [2] fa 0f [2] c7 }

  condition:
    any of them
}