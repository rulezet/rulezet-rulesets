rule TTP_XOR_MULT_DOSStub_6656 {
  strings:
    $key_6656 = { 32 3e [2] 46 26 [2] 01 24 [2] 46 35 [2] 08 39 [2] 04 33 [2] 13 38 [2] 08 76 [2] 35 }

  condition:
    any of them
}