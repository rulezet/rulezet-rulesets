rule TTP_XOR_MULT_DOSStub_dc37 {
  strings:
    $key_dc37 = { 88 5f [2] fc 47 [2] bb 45 [2] fc 54 [2] b2 58 [2] be 52 [2] a9 59 [2] b2 17 [2] 8f }

  condition:
    any of them
}