rule TTP_XOR_MULT_DOSStub_6600 {
  strings:
    $key_6600 = { 32 68 [2] 46 70 [2] 01 72 [2] 46 63 [2] 08 6f [2] 04 65 [2] 13 6e [2] 08 20 [2] 35 }

  condition:
    any of them
}