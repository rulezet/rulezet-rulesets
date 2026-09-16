rule TTP_XOR_MULT_DOSStub_d068 {
  strings:
    $key_d068 = { 84 00 [2] f0 18 [2] b7 1a [2] f0 0b [2] be 07 [2] b2 0d [2] a5 06 [2] be 48 [2] 83 }

  condition:
    any of them
}