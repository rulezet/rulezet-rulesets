rule TTP_XOR_MULT_DOSStub_d733 {
  strings:
    $key_d733 = { 83 5b [2] f7 43 [2] b0 41 [2] f7 50 [2] b9 5c [2] b5 56 [2] a2 5d [2] b9 13 [2] 84 }

  condition:
    any of them
}