rule TTP_XOR_MULT_DOSStub_941a {
  strings:
    $key_941a = { c0 72 [2] b4 6a [2] f3 68 [2] b4 79 [2] fa 75 [2] f6 7f [2] e1 74 [2] fa 3a [2] c7 }

  condition:
    any of them
}