rule TTP_XOR_MULT_DOSStub_1b30 {
  strings:
    $key_1b30 = { 4f 58 [2] 3b 40 [2] 7c 42 [2] 3b 53 [2] 75 5f [2] 79 55 [2] 6e 5e [2] 75 10 [2] 48 }

  condition:
    any of them
}