rule TTP_XOR_MULT_DOSStub_4b61 {
  strings:
    $key_4b61 = { 1f 09 [2] 6b 11 [2] 2c 13 [2] 6b 02 [2] 25 0e [2] 29 04 [2] 3e 0f [2] 25 41 [2] 18 }

  condition:
    any of them
}