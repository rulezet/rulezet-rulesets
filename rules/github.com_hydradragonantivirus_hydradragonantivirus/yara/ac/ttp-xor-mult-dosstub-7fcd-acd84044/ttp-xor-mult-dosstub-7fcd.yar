rule TTP_XOR_MULT_DOSStub_7fcd {
  strings:
    $key_7fcd = { 2b a5 [2] 5f bd [2] 18 bf [2] 5f ae [2] 11 a2 [2] 1d a8 [2] 0a a3 [2] 11 ed [2] 2c }

  condition:
    any of them
}