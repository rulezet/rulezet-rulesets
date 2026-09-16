rule TTP_XOR_MULT_DOSStub_0fcd {
  strings:
    $key_0fcd = { 5b a5 [2] 2f bd [2] 68 bf [2] 2f ae [2] 61 a2 [2] 6d a8 [2] 7a a3 [2] 61 ed [2] 5c }

  condition:
    any of them
}