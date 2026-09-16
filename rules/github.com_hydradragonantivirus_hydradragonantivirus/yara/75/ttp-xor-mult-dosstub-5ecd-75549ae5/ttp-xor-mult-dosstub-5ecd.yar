rule TTP_XOR_MULT_DOSStub_5ecd {
  strings:
    $key_5ecd = { 0a a5 [2] 7e bd [2] 39 bf [2] 7e ae [2] 30 a2 [2] 3c a8 [2] 2b a3 [2] 30 ed [2] 0d }

  condition:
    any of them
}