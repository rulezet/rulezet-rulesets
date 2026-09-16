rule TTP_XOR_MULT_DOSStub_2bf1 {
  strings:
    $key_2bf1 = { 7f 99 [2] 0b 81 [2] 4c 83 [2] 0b 92 [2] 45 9e [2] 49 94 [2] 5e 9f [2] 45 d1 [2] 78 }

  condition:
    any of them
}