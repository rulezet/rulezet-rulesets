rule TTP_XOR_MULT_DOSStub_2c77 {
  strings:
    $key_2c77 = { 78 1f [2] 0c 07 [2] 4b 05 [2] 0c 14 [2] 42 18 [2] 4e 12 [2] 59 19 [2] 42 57 [2] 7f }

  condition:
    any of them
}