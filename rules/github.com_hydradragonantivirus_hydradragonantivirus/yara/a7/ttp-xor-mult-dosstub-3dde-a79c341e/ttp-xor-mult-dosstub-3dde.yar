rule TTP_XOR_MULT_DOSStub_3dde {
  strings:
    $key_3dde = { 69 b6 [2] 1d ae [2] 5a ac [2] 1d bd [2] 53 b1 [2] 5f bb [2] 48 b0 [2] 53 fe [2] 6e }

  condition:
    any of them
}