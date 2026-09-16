rule TTP_XOR_MULT_DOSStub_2fde {
  strings:
    $key_2fde = { 7b b6 [2] 0f ae [2] 48 ac [2] 0f bd [2] 41 b1 [2] 4d bb [2] 5a b0 [2] 41 fe [2] 7c }

  condition:
    any of them
}