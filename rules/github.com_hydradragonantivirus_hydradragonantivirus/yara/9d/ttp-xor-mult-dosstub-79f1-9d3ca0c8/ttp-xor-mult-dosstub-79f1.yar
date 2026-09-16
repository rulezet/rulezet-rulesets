rule TTP_XOR_MULT_DOSStub_79f1 {
  strings:
    $key_79f1 = { 2d 99 [2] 59 81 [2] 1e 83 [2] 59 92 [2] 17 9e [2] 1b 94 [2] 0c 9f [2] 17 d1 [2] 2a }

  condition:
    any of them
}