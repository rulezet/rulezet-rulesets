rule TTP_XOR_MULT_DOSStub_1830 {
  strings:
    $key_1830 = { 4c 58 [2] 38 40 [2] 7f 42 [2] 38 53 [2] 76 5f [2] 7a 55 [2] 6d 5e [2] 76 10 [2] 4b }

  condition:
    any of them
}