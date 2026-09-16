rule TTP_XOR_MULT_DOSStub_6ce0 {
  strings:
    $key_6ce0 = { 38 88 [2] 4c 90 [2] 0b 92 [2] 4c 83 [2] 02 8f [2] 0e 85 [2] 19 8e [2] 02 c0 [2] 3f }

  condition:
    any of them
}