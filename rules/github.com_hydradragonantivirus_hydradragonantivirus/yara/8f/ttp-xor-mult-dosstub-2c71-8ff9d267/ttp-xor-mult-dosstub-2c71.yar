rule TTP_XOR_MULT_DOSStub_2c71 {
  strings:
    $key_2c71 = { 78 19 [2] 0c 01 [2] 4b 03 [2] 0c 12 [2] 42 1e [2] 4e 14 [2] 59 1f [2] 42 51 [2] 7f }

  condition:
    any of them
}