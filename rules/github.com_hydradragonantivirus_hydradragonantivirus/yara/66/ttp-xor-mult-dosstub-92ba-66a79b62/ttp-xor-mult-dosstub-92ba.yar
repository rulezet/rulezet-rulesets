rule TTP_XOR_MULT_DOSStub_92ba {
  strings:
    $key_92ba = { c6 d2 [2] b2 ca [2] f5 c8 [2] b2 d9 [2] fc d5 [2] f0 df [2] e7 d4 [2] fc 9a [2] c1 }

  condition:
    any of them
}