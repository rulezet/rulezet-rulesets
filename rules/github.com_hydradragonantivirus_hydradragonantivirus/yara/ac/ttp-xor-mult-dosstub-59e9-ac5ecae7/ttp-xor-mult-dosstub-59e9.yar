rule TTP_XOR_MULT_DOSStub_59e9 {
  strings:
    $key_59e9 = { 0d 81 [2] 79 99 [2] 3e 9b [2] 79 8a [2] 37 86 [2] 3b 8c [2] 2c 87 [2] 37 c9 [2] 0a }

  condition:
    any of them
}