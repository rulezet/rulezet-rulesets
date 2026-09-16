rule TTP_XOR_MULT_DOSStub_62f1 {
  strings:
    $key_62f1 = { 36 99 [2] 42 81 [2] 05 83 [2] 42 92 [2] 0c 9e [2] 00 94 [2] 17 9f [2] 0c d1 [2] 31 }

  condition:
    any of them
}