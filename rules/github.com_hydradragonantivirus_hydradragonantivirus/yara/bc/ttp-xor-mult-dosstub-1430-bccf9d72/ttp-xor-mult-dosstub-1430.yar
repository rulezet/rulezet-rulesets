rule TTP_XOR_MULT_DOSStub_1430 {
  strings:
    $key_1430 = { 40 58 [2] 34 40 [2] 73 42 [2] 34 53 [2] 7a 5f [2] 76 55 [2] 61 5e [2] 7a 10 [2] 47 }

  condition:
    any of them
}