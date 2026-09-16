rule TTP_XOR_MULT_DOSStub_2c37 {
  strings:
    $key_2c37 = { 78 5f [2] 0c 47 [2] 4b 45 [2] 0c 54 [2] 42 58 [2] 4e 52 [2] 59 59 [2] 42 17 [2] 7f }

  condition:
    any of them
}