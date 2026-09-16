rule TTP_XOR_MULT_DOSStub_4e77 {
  strings:
    $key_4e77 = { 1a 1f [2] 6e 07 [2] 29 05 [2] 6e 14 [2] 20 18 [2] 2c 12 [2] 3b 19 [2] 20 57 [2] 1d }

  condition:
    any of them
}