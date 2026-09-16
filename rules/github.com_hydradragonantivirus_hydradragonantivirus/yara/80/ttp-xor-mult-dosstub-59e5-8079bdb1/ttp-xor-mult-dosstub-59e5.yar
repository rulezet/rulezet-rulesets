rule TTP_XOR_MULT_DOSStub_59e5 {
  strings:
    $key_59e5 = { 0d 8d [2] 79 95 [2] 3e 97 [2] 79 86 [2] 37 8a [2] 3b 80 [2] 2c 8b [2] 37 c5 [2] 0a }

  condition:
    any of them
}