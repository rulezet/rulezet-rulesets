rule TTP_XOR_MULT_DOSStub_7946 {
  strings:
    $key_7946 = { 2d 2e [2] 59 36 [2] 1e 34 [2] 59 25 [2] 17 29 [2] 1b 23 [2] 0c 28 [2] 17 66 [2] 2a }

  condition:
    any of them
}