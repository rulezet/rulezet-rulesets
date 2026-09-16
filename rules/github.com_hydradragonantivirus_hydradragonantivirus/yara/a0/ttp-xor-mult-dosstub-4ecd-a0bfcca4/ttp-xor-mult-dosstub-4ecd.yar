rule TTP_XOR_MULT_DOSStub_4ecd {
  strings:
    $key_4ecd = { 1a a5 [2] 6e bd [2] 29 bf [2] 6e ae [2] 20 a2 [2] 2c a8 [2] 3b a3 [2] 20 ed [2] 1d }

  condition:
    any of them
}