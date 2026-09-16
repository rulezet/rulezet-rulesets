rule TTP_XOR_MULT_DOSStub_2c01 {
  strings:
    $key_2c01 = { 78 69 [2] 0c 71 [2] 4b 73 [2] 0c 62 [2] 42 6e [2] 4e 64 [2] 59 6f [2] 42 21 [2] 7f }

  condition:
    any of them
}