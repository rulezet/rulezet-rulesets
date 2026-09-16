rule TTP_XOR_MULT_DOSStub_2c30 {
  strings:
    $key_2c30 = { 78 58 [2] 0c 40 [2] 4b 42 [2] 0c 53 [2] 42 5f [2] 4e 55 [2] 59 5e [2] 42 10 [2] 7f }

  condition:
    any of them
}