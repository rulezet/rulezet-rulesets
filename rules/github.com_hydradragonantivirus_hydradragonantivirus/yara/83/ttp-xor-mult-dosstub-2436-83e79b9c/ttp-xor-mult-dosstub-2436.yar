rule TTP_XOR_MULT_DOSStub_2436 {
  strings:
    $key_2436 = { 70 5e [2] 04 46 [2] 43 44 [2] 04 55 [2] 4a 59 [2] 46 53 [2] 51 58 [2] 4a 16 [2] 77 }

  condition:
    any of them
}