rule TTP_XOR_MULT_DOSStub_d01a {
  strings:
    $key_d01a = { 84 72 [2] f0 6a [2] b7 68 [2] f0 79 [2] be 75 [2] b2 7f [2] a5 74 [2] be 3a [2] 83 }

  condition:
    any of them
}