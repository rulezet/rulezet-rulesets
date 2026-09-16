rule TTP_XOR_MULT_DOSStub_1531 {
  strings:
    $key_1531 = { 41 59 [2] 35 41 [2] 72 43 [2] 35 52 [2] 7b 5e [2] 77 54 [2] 60 5f [2] 7b 11 [2] 46 }

  condition:
    any of them
}