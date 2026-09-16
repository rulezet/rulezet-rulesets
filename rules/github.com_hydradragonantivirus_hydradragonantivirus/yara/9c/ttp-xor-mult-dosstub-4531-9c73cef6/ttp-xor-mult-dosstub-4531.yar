rule TTP_XOR_MULT_DOSStub_4531 {
  strings:
    $key_4531 = { 11 59 [2] 65 41 [2] 22 43 [2] 65 52 [2] 2b 5e [2] 27 54 [2] 30 5f [2] 2b 11 [2] 16 }

  condition:
    any of them
}