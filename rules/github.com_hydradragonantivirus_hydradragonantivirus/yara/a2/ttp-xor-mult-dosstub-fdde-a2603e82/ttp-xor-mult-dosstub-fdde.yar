rule TTP_XOR_MULT_DOSStub_fdde {
  strings:
    $key_fdde = { a9 b6 [2] dd ae [2] 9a ac [2] dd bd [2] 93 b1 [2] 9f bb [2] 88 b0 [2] 93 fe [2] ae }

  condition:
    any of them
}