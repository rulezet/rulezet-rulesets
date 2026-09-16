rule TTP_XOR_MULT_DOSStub_dc2b {
  strings:
    $key_dc2b = { 88 43 [2] fc 5b [2] bb 59 [2] fc 48 [2] b2 44 [2] be 4e [2] a9 45 [2] b2 0b [2] 8f }

  condition:
    any of them
}