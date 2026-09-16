rule TTP_XOR_MULT_DOSStub_d013 {
  strings:
    $key_d013 = { 84 7b [2] f0 63 [2] b7 61 [2] f0 70 [2] be 7c [2] b2 76 [2] a5 7d [2] be 33 [2] 83 }

  condition:
    any of them
}