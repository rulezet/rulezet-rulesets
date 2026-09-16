rule TTP_XOR_MULT_DOSStub_7dde {
  strings:
    $key_7dde = { 29 b6 [2] 5d ae [2] 1a ac [2] 5d bd [2] 13 b1 [2] 1f bb [2] 08 b0 [2] 13 fe [2] 2e }

  condition:
    any of them
}