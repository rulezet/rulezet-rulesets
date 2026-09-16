rule TTP_XOR_MULT_DOSStub_4ede {
  strings:
    $key_4ede = { 1a b6 [2] 6e ae [2] 29 ac [2] 6e bd [2] 20 b1 [2] 2c bb [2] 3b b0 [2] 20 fe [2] 1d }

  condition:
    any of them
}