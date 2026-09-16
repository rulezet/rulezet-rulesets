rule TTP_XOR_MULT_DOSStub_d010 {
  strings:
    $key_d010 = { 84 78 [2] f0 60 [2] b7 62 [2] f0 73 [2] be 7f [2] b2 75 [2] a5 7e [2] be 30 [2] 83 }

  condition:
    any of them
}