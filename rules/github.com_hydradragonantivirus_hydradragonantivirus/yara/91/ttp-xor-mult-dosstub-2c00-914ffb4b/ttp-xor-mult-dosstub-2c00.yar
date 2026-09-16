rule TTP_XOR_MULT_DOSStub_2c00 {
  strings:
    $key_2c00 = { 78 68 [2] 0c 70 [2] 4b 72 [2] 0c 63 [2] 42 6f [2] 4e 65 [2] 59 6e [2] 42 20 [2] 7f }

  condition:
    any of them
}