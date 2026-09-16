rule TTP_XOR_MULT_DOSStub_3ad5 {
  strings:
    $key_3ad5 = { 6e bd [2] 1a a5 [2] 5d a7 [2] 1a b6 [2] 54 ba [2] 58 b0 [2] 4f bb [2] 54 f5 [2] 69 }

  condition:
    any of them
}