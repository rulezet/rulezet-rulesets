rule TTP_XOR_MULT_DOSStub_2c1b {
  strings:
    $key_2c1b = { 78 73 [2] 0c 6b [2] 4b 69 [2] 0c 78 [2] 42 74 [2] 4e 7e [2] 59 75 [2] 42 3b [2] 7f }

  condition:
    any of them
}