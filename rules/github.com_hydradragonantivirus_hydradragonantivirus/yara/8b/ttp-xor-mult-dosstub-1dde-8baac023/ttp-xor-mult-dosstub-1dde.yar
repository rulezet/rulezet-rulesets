rule TTP_XOR_MULT_DOSStub_1dde {
  strings:
    $key_1dde = { 49 b6 [2] 3d ae [2] 7a ac [2] 3d bd [2] 73 b1 [2] 7f bb [2] 68 b0 [2] 73 fe [2] 4e }

  condition:
    any of them
}