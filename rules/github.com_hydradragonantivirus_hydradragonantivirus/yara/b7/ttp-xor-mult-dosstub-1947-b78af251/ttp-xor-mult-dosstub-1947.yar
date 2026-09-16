rule TTP_XOR_MULT_DOSStub_1947 {
  strings:
    $key_1947 = { 4d 2f [2] 39 37 [2] 7e 35 [2] 39 24 [2] 77 28 [2] 7b 22 [2] 6c 29 [2] 77 67 [2] 4a }

  condition:
    any of them
}