rule TTP_XOR_MULT_DOSStub_6dde {
  strings:
    $key_6dde = { 39 b6 [2] 4d ae [2] 0a ac [2] 4d bd [2] 03 b1 [2] 0f bb [2] 18 b0 [2] 03 fe [2] 3e }

  condition:
    any of them
}