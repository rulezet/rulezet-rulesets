rule TTP_XOR_MULT_DOSStub_0cec {
  strings:
    $key_0cec = { 58 84 [2] 2c 9c [2] 6b 9e [2] 2c 8f [2] 62 83 [2] 6e 89 [2] 79 82 [2] 62 cc [2] 5f }

  condition:
    any of them
}