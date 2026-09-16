rule TTP_XOR_MULT_DOSStub_dc0c {
  strings:
    $key_dc0c = { 88 64 [2] fc 7c [2] bb 7e [2] fc 6f [2] b2 63 [2] be 69 [2] a9 62 [2] b2 2c [2] 8f }

  condition:
    any of them
}