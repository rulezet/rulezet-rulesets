rule TTP_XOR_MULT_DOSStub_d047 {
  strings:
    $key_d047 = { 84 2f [2] f0 37 [2] b7 35 [2] f0 24 [2] be 28 [2] b2 22 [2] a5 29 [2] be 67 [2] 83 }

  condition:
    any of them
}