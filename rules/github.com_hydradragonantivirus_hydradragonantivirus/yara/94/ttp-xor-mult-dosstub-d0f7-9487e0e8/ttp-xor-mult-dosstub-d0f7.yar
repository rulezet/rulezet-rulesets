rule TTP_XOR_MULT_DOSStub_d0f7 {
  strings:
    $key_d0f7 = { 84 9f [2] f0 87 [2] b7 85 [2] f0 94 [2] be 98 [2] b2 92 [2] a5 99 [2] be d7 [2] 83 }

  condition:
    any of them
}