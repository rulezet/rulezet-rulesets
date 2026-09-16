rule TTP_XOR_MULT_DOSStub_62f6 {
  strings:
    $key_62f6 = { 36 9e [2] 42 86 [2] 05 84 [2] 42 95 [2] 0c 99 [2] 00 93 [2] 17 98 [2] 0c d6 [2] 31 }

  condition:
    any of them
}