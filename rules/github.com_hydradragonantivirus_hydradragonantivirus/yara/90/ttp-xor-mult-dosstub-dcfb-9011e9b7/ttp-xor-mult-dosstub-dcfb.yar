rule TTP_XOR_MULT_DOSStub_dcfb {
  strings:
    $key_dcfb = { 88 93 [2] fc 8b [2] bb 89 [2] fc 98 [2] b2 94 [2] be 9e [2] a9 95 [2] b2 db [2] 8f }

  condition:
    any of them
}