rule TTP_XOR_MULT_DOSStub_2530 {
  strings:
    $key_2530 = { 71 58 [2] 05 40 [2] 42 42 [2] 05 53 [2] 4b 5f [2] 47 55 [2] 50 5e [2] 4b 10 [2] 76 }

  condition:
    any of them
}