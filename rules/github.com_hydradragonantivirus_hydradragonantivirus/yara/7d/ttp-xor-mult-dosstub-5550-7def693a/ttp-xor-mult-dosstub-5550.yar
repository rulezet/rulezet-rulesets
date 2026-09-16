rule TTP_XOR_MULT_DOSStub_5550 {
  strings:
    $key_5550 = { 01 38 [2] 75 20 [2] 32 22 [2] 75 33 [2] 3b 3f [2] 37 35 [2] 20 3e [2] 3b 70 [2] 06 }

  condition:
    any of them
}