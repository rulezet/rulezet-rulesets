rule TTP_XOR_MULT_DOSStub_59fc {
  strings:
    $key_59fc = { 0d 94 [2] 79 8c [2] 3e 8e [2] 79 9f [2] 37 93 [2] 3b 99 [2] 2c 92 [2] 37 dc [2] 0a }

  condition:
    any of them
}