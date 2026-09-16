rule TTP_XOR_MULT_DOSStub_2c21 {
  strings:
    $key_2c21 = { 78 49 [2] 0c 51 [2] 4b 53 [2] 0c 42 [2] 42 4e [2] 4e 44 [2] 59 4f [2] 42 01 [2] 7f }

  condition:
    any of them
}