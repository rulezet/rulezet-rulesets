rule TTP_XOR_MULT_DOSStub_dcfc {
  strings:
    $key_dcfc = { 88 94 [2] fc 8c [2] bb 8e [2] fc 9f [2] b2 93 [2] be 99 [2] a9 92 [2] b2 dc [2] 8f }

  condition:
    any of them
}