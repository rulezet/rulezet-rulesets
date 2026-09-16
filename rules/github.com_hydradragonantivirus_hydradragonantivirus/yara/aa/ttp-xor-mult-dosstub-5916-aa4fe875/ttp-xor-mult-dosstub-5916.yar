rule TTP_XOR_MULT_DOSStub_5916 {
  strings:
    $key_5916 = { 0d 7e [2] 79 66 [2] 3e 64 [2] 79 75 [2] 37 79 [2] 3b 73 [2] 2c 78 [2] 37 36 [2] 0a }

  condition:
    any of them
}