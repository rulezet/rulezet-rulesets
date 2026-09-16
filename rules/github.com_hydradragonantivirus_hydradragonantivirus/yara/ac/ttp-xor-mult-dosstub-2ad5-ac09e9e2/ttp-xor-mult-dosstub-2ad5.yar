rule TTP_XOR_MULT_DOSStub_2ad5 {
  strings:
    $key_2ad5 = { 7e bd [2] 0a a5 [2] 4d a7 [2] 0a b6 [2] 44 ba [2] 48 b0 [2] 5f bb [2] 44 f5 [2] 79 }

  condition:
    any of them
}