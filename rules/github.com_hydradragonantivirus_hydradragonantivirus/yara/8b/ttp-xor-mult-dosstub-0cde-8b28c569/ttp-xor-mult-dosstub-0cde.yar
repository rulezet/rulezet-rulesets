rule TTP_XOR_MULT_DOSStub_0cde {
  strings:
    $key_0cde = { 58 b6 [2] 2c ae [2] 6b ac [2] 2c bd [2] 62 b1 [2] 6e bb [2] 79 b0 [2] 62 fe [2] 5f }

  condition:
    any of them
}