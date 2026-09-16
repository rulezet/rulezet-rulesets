rule TTP_XOR_MULT_DOSStub_5217 {
  strings:
    $key_5217 = { 06 7f [2] 72 67 [2] 35 65 [2] 72 74 [2] 3c 78 [2] 30 72 [2] 27 79 [2] 3c 37 [2] 01 }

  condition:
    any of them
}