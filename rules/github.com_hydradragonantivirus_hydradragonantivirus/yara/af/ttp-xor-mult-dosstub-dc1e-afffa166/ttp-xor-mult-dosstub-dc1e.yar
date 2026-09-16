rule TTP_XOR_MULT_DOSStub_dc1e {
  strings:
    $key_dc1e = { 88 76 [2] fc 6e [2] bb 6c [2] fc 7d [2] b2 71 [2] be 7b [2] a9 70 [2] b2 3e [2] 8f }

  condition:
    any of them
}