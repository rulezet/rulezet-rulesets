rule TTP_XOR_MULT_DOSStub_2cf1 {
  strings:
    $key_2cf1 = { 78 99 [2] 0c 81 [2] 4b 83 [2] 0c 92 [2] 42 9e [2] 4e 94 [2] 59 9f [2] 42 d1 [2] 7f }

  condition:
    any of them
}