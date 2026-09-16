rule TTP_XOR_MULT_DOSStub_4567 {
  strings:
    $key_4567 = { 11 0f [2] 65 17 [2] 22 15 [2] 65 04 [2] 2b 08 [2] 27 02 [2] 30 09 [2] 2b 47 [2] 16 }

  condition:
    any of them
}