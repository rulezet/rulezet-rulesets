rule TTP_XOR_MULT_DOSStub_d037 {
  strings:
    $key_d037 = { 84 5f [2] f0 47 [2] b7 45 [2] f0 54 [2] be 58 [2] b2 52 [2] a5 59 [2] be 17 [2] 83 }

  condition:
    any of them
}