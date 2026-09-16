rule TTP_XOR_MULT_DOSStub_d065 {
  strings:
    $key_d065 = { 84 0d [2] f0 15 [2] b7 17 [2] f0 06 [2] be 0a [2] b2 00 [2] a5 0b [2] be 45 [2] 83 }

  condition:
    any of them
}