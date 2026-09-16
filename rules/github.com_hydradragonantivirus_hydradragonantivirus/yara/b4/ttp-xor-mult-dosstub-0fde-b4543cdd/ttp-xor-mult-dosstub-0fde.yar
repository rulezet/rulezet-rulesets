rule TTP_XOR_MULT_DOSStub_0fde {
  strings:
    $key_0fde = { 5b b6 [2] 2f ae [2] 68 ac [2] 2f bd [2] 61 b1 [2] 6d bb [2] 7a b0 [2] 61 fe [2] 5c }

  condition:
    any of them
}