rule TTP_XOR_MULT_DOSStub_d0ba {
  strings:
    $key_d0ba = { 84 d2 [2] f0 ca [2] b7 c8 [2] f0 d9 [2] be d5 [2] b2 df [2] a5 d4 [2] be 9a [2] 83 }

  condition:
    any of them
}