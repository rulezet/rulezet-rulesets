rule TTP_XOR_MULT_DOSStub_1ecd {
  strings:
    $key_1ecd = { 4a a5 [2] 3e bd [2] 79 bf [2] 3e ae [2] 70 a2 [2] 7c a8 [2] 6b a3 [2] 70 ed [2] 4d }

  condition:
    any of them
}