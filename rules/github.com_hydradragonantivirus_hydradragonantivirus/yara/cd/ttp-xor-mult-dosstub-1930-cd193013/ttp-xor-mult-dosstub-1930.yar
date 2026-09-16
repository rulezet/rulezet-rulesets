rule TTP_XOR_MULT_DOSStub_1930 {
  strings:
    $key_1930 = { 4d 58 [2] 39 40 [2] 7e 42 [2] 39 53 [2] 77 5f [2] 7b 55 [2] 6c 5e [2] 77 10 [2] 4a }

  condition:
    any of them
}