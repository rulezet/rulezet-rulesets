rule TTP_XOR_MULT_DOSStub_d04a {
  strings:
    $key_d04a = { 84 22 [2] f0 3a [2] b7 38 [2] f0 29 [2] be 25 [2] b2 2f [2] a5 24 [2] be 6a [2] 83 }

  condition:
    any of them
}