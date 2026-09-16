rule TTP_XOR_MULT_DOSStub_dc3b {
  strings:
    $key_dc3b = { 88 53 [2] fc 4b [2] bb 49 [2] fc 58 [2] b2 54 [2] be 5e [2] a9 55 [2] b2 1b [2] 8f }

  condition:
    any of them
}