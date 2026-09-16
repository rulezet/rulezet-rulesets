rule TTP_XOR_MULT_DOSStub_1b70 {
  strings:
    $key_1b70 = { 4f 18 [2] 3b 00 [2] 7c 02 [2] 3b 13 [2] 75 1f [2] 79 15 [2] 6e 1e [2] 75 50 [2] 48 }

  condition:
    any of them
}