rule TTP_XOR_MULT_DOSStub_4530 {
  strings:
    $key_4530 = { 11 58 [2] 65 40 [2] 22 42 [2] 65 53 [2] 2b 5f [2] 27 55 [2] 30 5e [2] 2b 10 [2] 16 }

  condition:
    any of them
}