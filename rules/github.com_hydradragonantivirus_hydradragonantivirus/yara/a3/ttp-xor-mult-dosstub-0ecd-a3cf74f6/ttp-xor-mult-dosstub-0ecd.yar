rule TTP_XOR_MULT_DOSStub_0ecd {
  strings:
    $key_0ecd = { 5a a5 [2] 2e bd [2] 69 bf [2] 2e ae [2] 60 a2 [2] 6c a8 [2] 7b a3 [2] 60 ed [2] 5d }

  condition:
    any of them
}