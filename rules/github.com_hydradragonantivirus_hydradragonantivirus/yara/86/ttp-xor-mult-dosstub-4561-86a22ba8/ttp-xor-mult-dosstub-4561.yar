rule TTP_XOR_MULT_DOSStub_4561 {
  strings:
    $key_4561 = { 11 09 [2] 65 11 [2] 22 13 [2] 65 02 [2] 2b 0e [2] 27 04 [2] 30 0f [2] 2b 41 [2] 16 }

  condition:
    any of them
}