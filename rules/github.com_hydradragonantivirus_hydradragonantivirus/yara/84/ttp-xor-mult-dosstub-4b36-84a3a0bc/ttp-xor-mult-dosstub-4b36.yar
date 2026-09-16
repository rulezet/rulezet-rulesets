rule TTP_XOR_MULT_DOSStub_4b36 {
  strings:
    $key_4b36 = { 1f 5e [2] 6b 46 [2] 2c 44 [2] 6b 55 [2] 25 59 [2] 29 53 [2] 3e 58 [2] 25 16 [2] 18 }

  condition:
    any of them
}