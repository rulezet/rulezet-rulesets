rule TTP_XOR_MULT_DOSStub_dc2c {
  strings:
    $key_dc2c = { 88 44 [2] fc 5c [2] bb 5e [2] fc 4f [2] b2 43 [2] be 49 [2] a9 42 [2] b2 0c [2] 8f }

  condition:
    any of them
}