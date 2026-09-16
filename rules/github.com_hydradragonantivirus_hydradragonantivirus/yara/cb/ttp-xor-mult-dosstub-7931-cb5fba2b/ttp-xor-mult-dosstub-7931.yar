rule TTP_XOR_MULT_DOSStub_7931 {
  strings:
    $key_7931 = { 2d 59 [2] 59 41 [2] 1e 43 [2] 59 52 [2] 17 5e [2] 1b 54 [2] 0c 5f [2] 17 11 [2] 2a }

  condition:
    any of them
}