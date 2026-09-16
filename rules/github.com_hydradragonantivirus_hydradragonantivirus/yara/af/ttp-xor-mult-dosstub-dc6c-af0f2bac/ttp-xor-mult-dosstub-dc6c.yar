rule TTP_XOR_MULT_DOSStub_dc6c {
  strings:
    $key_dc6c = { 88 04 [2] fc 1c [2] bb 1e [2] fc 0f [2] b2 03 [2] be 09 [2] a9 02 [2] b2 4c [2] 8f }

  condition:
    any of them
}