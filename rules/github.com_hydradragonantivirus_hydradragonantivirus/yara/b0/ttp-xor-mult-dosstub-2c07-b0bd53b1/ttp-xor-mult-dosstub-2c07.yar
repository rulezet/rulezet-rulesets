rule TTP_XOR_MULT_DOSStub_2c07 {
  strings:
    $key_2c07 = { 78 6f [2] 0c 77 [2] 4b 75 [2] 0c 64 [2] 42 68 [2] 4e 62 [2] 59 69 [2] 42 27 [2] 7f }

  condition:
    any of them
}