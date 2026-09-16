rule TTP_XOR_MULT_DOSStub_dc29 {
  strings:
    $key_dc29 = { 88 41 [2] fc 59 [2] bb 5b [2] fc 4a [2] b2 46 [2] be 4c [2] a9 47 [2] b2 09 [2] 8f }

  condition:
    any of them
}