rule TTP_XOR_MULT_DOSStub_7947 {
  strings:
    $key_7947 = { 2d 2f [2] 59 37 [2] 1e 35 [2] 59 24 [2] 17 28 [2] 1b 22 [2] 0c 29 [2] 17 67 [2] 2a }

  condition:
    any of them
}