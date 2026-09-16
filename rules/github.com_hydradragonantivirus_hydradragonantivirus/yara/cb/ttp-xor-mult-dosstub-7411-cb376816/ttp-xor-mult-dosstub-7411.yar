rule TTP_XOR_MULT_DOSStub_7411 {
  strings:
    $key_7411 = { 20 79 [2] 54 61 [2] 13 63 [2] 54 72 [2] 1a 7e [2] 16 74 [2] 01 7f [2] 1a 31 [2] 27 }

  condition:
    any of them
}