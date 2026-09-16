rule TTP_XOR_MULT_DOSStub_1550 {
  strings:
    $key_1550 = { 41 38 [2] 35 20 [2] 72 22 [2] 35 33 [2] 7b 3f [2] 77 35 [2] 60 3e [2] 7b 70 [2] 46 }

  condition:
    any of them
}