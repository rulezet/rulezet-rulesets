rule TTP_XOR_MULT_DOSStub_dc66 {
  strings:
    $key_dc66 = { 88 0e [2] fc 16 [2] bb 14 [2] fc 05 [2] b2 09 [2] be 03 [2] a9 08 [2] b2 46 [2] 8f }

  condition:
    any of them
}