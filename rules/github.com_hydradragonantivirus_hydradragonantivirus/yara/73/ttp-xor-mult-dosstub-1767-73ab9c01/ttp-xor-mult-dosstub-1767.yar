rule TTP_XOR_MULT_DOSStub_1767 {
  strings:
    $key_1767 = { 43 0f [2] 37 17 [2] 70 15 [2] 37 04 [2] 79 08 [2] 75 02 [2] 62 09 [2] 79 47 [2] 44 }

  condition:
    any of them
}