rule TTP_XOR_MULT_DOSStub_79f6 {
  strings:
    $key_79f6 = { 2d 9e [2] 59 86 [2] 1e 84 [2] 59 95 [2] 17 99 [2] 1b 93 [2] 0c 98 [2] 17 d6 [2] 2a }

  condition:
    any of them
}