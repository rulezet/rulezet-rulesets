rule TTP_XOR_MULT_DOSStub_dc64 {
  strings:
    $key_dc64 = { 88 0c [2] fc 14 [2] bb 16 [2] fc 07 [2] b2 0b [2] be 01 [2] a9 0a [2] b2 44 [2] 8f }

  condition:
    any of them
}