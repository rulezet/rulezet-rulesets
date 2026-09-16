rule TTP_XOR_MULT_DOSStub_1bf6 {
  strings:
    $key_1bf6 = { 4f 9e [2] 3b 86 [2] 7c 84 [2] 3b 95 [2] 75 99 [2] 79 93 [2] 6e 98 [2] 75 d6 [2] 48 }

  condition:
    any of them
}