rule TTP_XOR_MULT_DOSStub_0b36 {
  strings:
    $key_0b36 = { 5f 5e [2] 2b 46 [2] 6c 44 [2] 2b 55 [2] 65 59 [2] 69 53 [2] 7e 58 [2] 65 16 [2] 58 }

  condition:
    any of them
}