rule TTP_XOR_MULT_DOSStub_59a8 {
  strings:
    $key_59a8 = { 0d c0 [2] 79 d8 [2] 3e da [2] 79 cb [2] 37 c7 [2] 3b cd [2] 2c c6 [2] 37 88 [2] 0a }

  condition:
    any of them
}