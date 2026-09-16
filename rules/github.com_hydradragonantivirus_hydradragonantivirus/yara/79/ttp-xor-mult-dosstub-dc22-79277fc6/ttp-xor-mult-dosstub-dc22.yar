rule TTP_XOR_MULT_DOSStub_dc22 {
  strings:
    $key_dc22 = { 88 4a [2] fc 52 [2] bb 50 [2] fc 41 [2] b2 4d [2] be 47 [2] a9 4c [2] b2 02 [2] 8f }

  condition:
    any of them
}