rule TTP_XOR_MULT_DOSStub_59a2 {
  strings:
    $key_59a2 = { 0d ca [2] 79 d2 [2] 3e d0 [2] 79 c1 [2] 37 cd [2] 3b c7 [2] 2c cc [2] 37 82 [2] 0a }

  condition:
    any of them
}