rule TTP_XOR_MULT_DOSStub_2c5b {
  strings:
    $key_2c5b = { 78 33 [2] 0c 2b [2] 4b 29 [2] 0c 38 [2] 42 34 [2] 4e 3e [2] 59 35 [2] 42 7b [2] 7f }

  condition:
    any of them
}