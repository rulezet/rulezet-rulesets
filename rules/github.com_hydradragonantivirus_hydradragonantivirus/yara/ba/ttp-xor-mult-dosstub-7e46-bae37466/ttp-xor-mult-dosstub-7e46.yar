rule TTP_XOR_MULT_DOSStub_7e46 {
  strings:
    $key_7e46 = { 2a 2e [2] 5e 36 [2] 19 34 [2] 5e 25 [2] 10 29 [2] 1c 23 [2] 0b 28 [2] 10 66 [2] 2d }

  condition:
    any of them
}