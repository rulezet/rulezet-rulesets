rule TTP_XOR_MULT_DOSStub_dcce {
  strings:
    $key_dcce = { 88 a6 [2] fc be [2] bb bc [2] fc ad [2] b2 a1 [2] be ab [2] a9 a0 [2] b2 ee [2] 8f }

  condition:
    any of them
}