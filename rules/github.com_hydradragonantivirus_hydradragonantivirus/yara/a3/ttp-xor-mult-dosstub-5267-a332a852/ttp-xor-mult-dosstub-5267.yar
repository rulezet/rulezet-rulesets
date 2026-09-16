rule TTP_XOR_MULT_DOSStub_5267 {
  strings:
    $key_5267 = { 06 0f [2] 72 17 [2] 35 15 [2] 72 04 [2] 3c 08 [2] 30 02 [2] 27 09 [2] 3c 47 [2] 01 }

  condition:
    any of them
}