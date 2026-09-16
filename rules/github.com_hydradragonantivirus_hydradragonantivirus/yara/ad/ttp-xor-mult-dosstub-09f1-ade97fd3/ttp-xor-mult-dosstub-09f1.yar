rule TTP_XOR_MULT_DOSStub_09f1 {
  strings:
    $key_09f1 = { 5d 99 [2] 29 81 [2] 6e 83 [2] 29 92 [2] 67 9e [2] 6b 94 [2] 7c 9f [2] 67 d1 [2] 5a }

  condition:
    any of them
}