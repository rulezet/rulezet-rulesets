rule TTP_XOR_MULT_DOSStub_6c61 {
  strings:
    $key_6c61 = { 38 09 [2] 4c 11 [2] 0b 13 [2] 4c 02 [2] 02 0e [2] 0e 04 [2] 19 0f [2] 02 41 [2] 3f }

  condition:
    any of them
}