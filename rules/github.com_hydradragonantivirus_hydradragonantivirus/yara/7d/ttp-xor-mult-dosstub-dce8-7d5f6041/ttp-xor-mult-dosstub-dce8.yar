rule TTP_XOR_MULT_DOSStub_dce8 {
  strings:
    $key_dce8 = { 88 80 [2] fc 98 [2] bb 9a [2] fc 8b [2] b2 87 [2] be 8d [2] a9 86 [2] b2 c8 [2] 8f }

  condition:
    any of them
}