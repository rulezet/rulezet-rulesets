rule TTP_XOR_MULT_DOSStub_59e1 {
  strings:
    $key_59e1 = { 0d 89 [2] 79 91 [2] 3e 93 [2] 79 82 [2] 37 8e [2] 3b 84 [2] 2c 8f [2] 37 c1 [2] 0a }

  condition:
    any of them
}