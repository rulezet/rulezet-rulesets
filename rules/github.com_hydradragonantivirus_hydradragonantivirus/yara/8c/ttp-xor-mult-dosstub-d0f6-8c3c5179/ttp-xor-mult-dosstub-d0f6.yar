rule TTP_XOR_MULT_DOSStub_d0f6 {
  strings:
    $key_d0f6 = { 84 9e [2] f0 86 [2] b7 84 [2] f0 95 [2] be 99 [2] b2 93 [2] a5 98 [2] be d6 [2] 83 }

  condition:
    any of them
}