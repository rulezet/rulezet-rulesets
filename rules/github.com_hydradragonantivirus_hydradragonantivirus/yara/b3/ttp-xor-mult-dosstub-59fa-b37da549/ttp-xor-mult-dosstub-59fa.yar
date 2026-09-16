rule TTP_XOR_MULT_DOSStub_59fa {
  strings:
    $key_59fa = { 0d 92 [2] 79 8a [2] 3e 88 [2] 79 99 [2] 37 95 [2] 3b 9f [2] 2c 94 [2] 37 da [2] 0a }

  condition:
    any of them
}