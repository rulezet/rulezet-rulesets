rule TTP_XOR_MULT_DOSStub_dc24 {
  strings:
    $key_dc24 = { 88 4c [2] fc 54 [2] bb 56 [2] fc 47 [2] b2 4b [2] be 41 [2] a9 4a [2] b2 04 [2] 8f }

  condition:
    any of them
}