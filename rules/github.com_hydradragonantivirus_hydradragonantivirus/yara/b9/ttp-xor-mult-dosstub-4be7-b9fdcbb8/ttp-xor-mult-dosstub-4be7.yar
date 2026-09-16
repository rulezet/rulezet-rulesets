rule TTP_XOR_MULT_DOSStub_4be7 {
  strings:
    $key_4be7 = { 1f 8f [2] 6b 97 [2] 2c 95 [2] 6b 84 [2] 25 88 [2] 29 82 [2] 3e 89 [2] 25 c7 [2] 18 }

  condition:
    any of them
}