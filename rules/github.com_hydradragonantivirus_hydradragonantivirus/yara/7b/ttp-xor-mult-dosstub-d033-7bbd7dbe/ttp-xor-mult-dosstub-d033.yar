rule TTP_XOR_MULT_DOSStub_d033 {
  strings:
    $key_d033 = { 84 5b [2] f0 43 [2] b7 41 [2] f0 50 [2] be 5c [2] b2 56 [2] a5 5d [2] be 13 [2] 83 }

  condition:
    any of them
}