rule TTP_XOR_MULT_DOSStub_7461 {
  strings:
    $key_7461 = { 20 09 [2] 54 11 [2] 13 13 [2] 54 02 [2] 1a 0e [2] 16 04 [2] 01 0f [2] 1a 41 [2] 27 }

  condition:
    any of them
}