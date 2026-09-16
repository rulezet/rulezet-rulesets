rule TTP_XOR_MULT_DOSStub_7261 {
  strings:
    $key_7261 = { 26 09 [2] 52 11 [2] 15 13 [2] 52 02 [2] 1c 0e [2] 10 04 [2] 07 0f [2] 1c 41 [2] 21 }

  condition:
    any of them
}