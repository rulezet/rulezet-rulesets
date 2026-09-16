rule TTP_XOR_MULT_DOSStub_6606 {
  strings:
    $key_6606 = { 32 6e [2] 46 76 [2] 01 74 [2] 46 65 [2] 08 69 [2] 04 63 [2] 13 68 [2] 08 26 [2] 35 }

  condition:
    any of them
}