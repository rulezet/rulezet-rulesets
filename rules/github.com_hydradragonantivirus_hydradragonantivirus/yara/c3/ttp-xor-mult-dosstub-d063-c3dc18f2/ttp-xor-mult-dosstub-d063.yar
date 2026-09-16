rule TTP_XOR_MULT_DOSStub_d063 {
  strings:
    $key_d063 = { 84 0b [2] f0 13 [2] b7 11 [2] f0 00 [2] be 0c [2] b2 06 [2] a5 0d [2] be 43 [2] 83 }

  condition:
    any of them
}