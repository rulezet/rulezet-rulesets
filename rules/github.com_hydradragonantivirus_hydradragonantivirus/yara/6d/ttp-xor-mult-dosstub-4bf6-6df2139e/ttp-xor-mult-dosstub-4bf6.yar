rule TTP_XOR_MULT_DOSStub_4bf6 {
  strings:
    $key_4bf6 = { 1f 9e [2] 6b 86 [2] 2c 84 [2] 6b 95 [2] 25 99 [2] 29 93 [2] 3e 98 [2] 25 d6 [2] 18 }

  condition:
    any of them
}