rule TTP_XOR_MULT_DOSStub_dc69 {
  strings:
    $key_dc69 = { 88 01 [2] fc 19 [2] bb 1b [2] fc 0a [2] b2 06 [2] be 0c [2] a9 07 [2] b2 49 [2] 8f }

  condition:
    any of them
}