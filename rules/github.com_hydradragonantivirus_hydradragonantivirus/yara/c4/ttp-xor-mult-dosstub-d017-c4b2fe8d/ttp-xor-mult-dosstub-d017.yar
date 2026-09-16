rule TTP_XOR_MULT_DOSStub_d017 {
  strings:
    $key_d017 = { 84 7f [2] f0 67 [2] b7 65 [2] f0 74 [2] be 78 [2] b2 72 [2] a5 79 [2] be 37 [2] 83 }

  condition:
    any of them
}