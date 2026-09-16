rule TTP_XOR_MULT_DOSStub_1261 {
  strings:
    $key_1261 = { 46 09 [2] 32 11 [2] 75 13 [2] 32 02 [2] 7c 0e [2] 70 04 [2] 67 0f [2] 7c 41 [2] 41 }

  condition:
    any of them
}