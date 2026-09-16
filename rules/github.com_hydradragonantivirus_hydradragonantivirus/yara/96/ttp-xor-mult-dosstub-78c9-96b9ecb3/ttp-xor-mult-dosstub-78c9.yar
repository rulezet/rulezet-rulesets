rule TTP_XOR_MULT_DOSStub_78c9 {
  strings:
    $key_78c9 = { 2c a1 [2] 58 b9 [2] 1f bb [2] 58 aa [2] 16 a6 [2] 1a ac [2] 0d a7 [2] 16 e9 [2] 2b }

  condition:
    any of them
}