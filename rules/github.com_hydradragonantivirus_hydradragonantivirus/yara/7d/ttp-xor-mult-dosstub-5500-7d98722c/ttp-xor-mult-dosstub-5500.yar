rule TTP_XOR_MULT_DOSStub_5500 {
  strings:
    $key_5500 = { 01 68 [2] 75 70 [2] 32 72 [2] 75 63 [2] 3b 6f [2] 37 65 [2] 20 6e [2] 3b 20 [2] 06 }

  condition:
    any of them
}