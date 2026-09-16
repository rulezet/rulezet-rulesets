rule TTP_XOR_MULT_DOSStub_947a {
  strings:
    $key_947a = { c0 12 [2] b4 0a [2] f3 08 [2] b4 19 [2] fa 15 [2] f6 1f [2] e1 14 [2] fa 5a [2] c7 }

  condition:
    any of them
}