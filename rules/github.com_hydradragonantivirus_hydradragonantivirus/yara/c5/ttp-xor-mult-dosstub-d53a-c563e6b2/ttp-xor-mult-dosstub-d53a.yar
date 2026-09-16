rule TTP_XOR_MULT_DOSStub_d53a {
  strings:
    $key_d53a = { 81 52 [2] f5 4a [2] b2 48 [2] f5 59 [2] bb 55 [2] b7 5f [2] a0 54 [2] bb 1a [2] 86 }

  condition:
    any of them
}