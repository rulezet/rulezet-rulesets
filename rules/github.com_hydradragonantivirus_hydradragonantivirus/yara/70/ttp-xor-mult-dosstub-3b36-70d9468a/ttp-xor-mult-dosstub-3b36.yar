rule TTP_XOR_MULT_DOSStub_3b36 {
  strings:
    $key_3b36 = { 6f 5e [2] 1b 46 [2] 5c 44 [2] 1b 55 [2] 55 59 [2] 59 53 [2] 4e 58 [2] 55 16 [2] 68 }

  condition:
    any of them
}