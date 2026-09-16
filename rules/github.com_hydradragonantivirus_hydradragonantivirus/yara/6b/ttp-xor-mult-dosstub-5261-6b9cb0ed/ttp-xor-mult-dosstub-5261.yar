rule TTP_XOR_MULT_DOSStub_5261 {
  strings:
    $key_5261 = { 06 09 [2] 72 11 [2] 35 13 [2] 72 02 [2] 3c 0e [2] 30 04 [2] 27 0f [2] 3c 41 [2] 01 }

  condition:
    any of them
}