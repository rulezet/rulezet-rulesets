rule TTP_XOR_MULT_DOSStub_7561 {
  strings:
    $key_7561 = { 21 09 [2] 55 11 [2] 12 13 [2] 55 02 [2] 1b 0e [2] 17 04 [2] 00 0f [2] 1b 41 [2] 26 }

  condition:
    any of them
}