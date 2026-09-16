rule TTP_XOR_MULT_DOSStub_4ec3 {
  strings:
    $key_4ec3 = { 1a ab [2] 6e b3 [2] 29 b1 [2] 6e a0 [2] 20 ac [2] 2c a6 [2] 3b ad [2] 20 e3 [2] 1d }

  condition:
    any of them
}