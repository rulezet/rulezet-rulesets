rule TTP_XOR_MULT_DOSStub_d014 {
  strings:
    $key_d014 = { 84 7c [2] f0 64 [2] b7 66 [2] f0 77 [2] be 7b [2] b2 71 [2] a5 7a [2] be 34 [2] 83 }

  condition:
    any of them
}