rule TTP_XOR_MULT_DOSStub_d07a {
  strings:
    $key_d07a = { 84 12 [2] f0 0a [2] b7 08 [2] f0 19 [2] be 15 [2] b2 1f [2] a5 14 [2] be 5a [2] 83 }

  condition:
    any of them
}