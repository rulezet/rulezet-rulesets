rule TTP_XOR_MULT_DOSStub_6ad5 {
  strings:
    $key_6ad5 = { 3e bd [2] 4a a5 [2] 0d a7 [2] 4a b6 [2] 04 ba [2] 08 b0 [2] 1f bb [2] 04 f5 [2] 39 }

  condition:
    any of them
}