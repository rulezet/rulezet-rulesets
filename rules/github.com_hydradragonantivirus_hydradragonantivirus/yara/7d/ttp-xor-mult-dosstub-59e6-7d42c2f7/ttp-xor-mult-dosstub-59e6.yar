rule TTP_XOR_MULT_DOSStub_59e6 {
  strings:
    $key_59e6 = { 0d 8e [2] 79 96 [2] 3e 94 [2] 79 85 [2] 37 89 [2] 3b 83 [2] 2c 88 [2] 37 c6 [2] 0a }

  condition:
    any of them
}