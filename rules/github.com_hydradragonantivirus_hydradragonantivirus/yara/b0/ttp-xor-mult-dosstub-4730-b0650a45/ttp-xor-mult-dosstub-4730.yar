rule TTP_XOR_MULT_DOSStub_4730 {
  strings:
    $key_4730 = { 13 58 [2] 67 40 [2] 20 42 [2] 67 53 [2] 29 5f [2] 25 55 [2] 32 5e [2] 29 10 [2] 14 }

  condition:
    any of them
}