rule TTP_XOR_MULT_DOSStub_59e3 {
  strings:
    $key_59e3 = { 0d 8b [2] 79 93 [2] 3e 91 [2] 79 80 [2] 37 8c [2] 3b 86 [2] 2c 8d [2] 37 c3 [2] 0a }

  condition:
    any of them
}