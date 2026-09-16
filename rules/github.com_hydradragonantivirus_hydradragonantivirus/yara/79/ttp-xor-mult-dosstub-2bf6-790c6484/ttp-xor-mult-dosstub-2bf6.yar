rule TTP_XOR_MULT_DOSStub_2bf6 {
  strings:
    $key_2bf6 = { 7f 9e [2] 0b 86 [2] 4c 84 [2] 0b 95 [2] 45 99 [2] 49 93 [2] 5e 98 [2] 45 d6 [2] 78 }

  condition:
    any of them
}