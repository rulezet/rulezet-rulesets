rule TTP_XOR_MULT_DOSStub_d0f0 {
  strings:
    $key_d0f0 = { 84 98 [2] f0 80 [2] b7 82 [2] f0 93 [2] be 9f [2] b2 95 [2] a5 9e [2] be d0 [2] 83 }

  condition:
    any of them
}