rule TTP_XOR_MULT_DOSStub_0530 {
  strings:
    $key_0530 = { 51 58 [2] 25 40 [2] 62 42 [2] 25 53 [2] 6b 5f [2] 67 55 [2] 70 5e [2] 6b 10 [2] 56 }

  condition:
    any of them
}