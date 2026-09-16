rule TTP_XOR_MULT_DOSStub_0ad5 {
  strings:
    $key_0ad5 = { 5e bd [2] 2a a5 [2] 6d a7 [2] 2a b6 [2] 64 ba [2] 68 b0 [2] 7f bb [2] 64 f5 [2] 59 }

  condition:
    any of them
}