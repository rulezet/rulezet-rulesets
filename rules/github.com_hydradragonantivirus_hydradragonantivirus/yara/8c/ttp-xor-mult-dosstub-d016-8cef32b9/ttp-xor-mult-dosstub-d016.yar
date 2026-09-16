rule TTP_XOR_MULT_DOSStub_d016 {
  strings:
    $key_d016 = { 84 7e [2] f0 66 [2] b7 64 [2] f0 75 [2] be 79 [2] b2 73 [2] a5 78 [2] be 36 [2] 83 }

  condition:
    any of them
}