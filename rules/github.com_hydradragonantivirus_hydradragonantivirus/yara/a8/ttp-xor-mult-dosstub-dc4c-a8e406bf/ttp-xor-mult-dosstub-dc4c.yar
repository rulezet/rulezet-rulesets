rule TTP_XOR_MULT_DOSStub_dc4c {
  strings:
    $key_dc4c = { 88 24 [2] fc 3c [2] bb 3e [2] fc 2f [2] b2 23 [2] be 29 [2] a9 22 [2] b2 6c [2] 8f }

  condition:
    any of them
}