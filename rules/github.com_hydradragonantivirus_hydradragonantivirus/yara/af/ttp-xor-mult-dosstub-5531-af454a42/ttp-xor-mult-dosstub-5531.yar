rule TTP_XOR_MULT_DOSStub_5531 {
  strings:
    $key_5531 = { 01 59 [2] 75 41 [2] 32 43 [2] 75 52 [2] 3b 5e [2] 37 54 [2] 20 5f [2] 3b 11 [2] 06 }

  condition:
    any of them
}