rule TTP_XOR_MULT_DOSStub_1cde {
  strings:
    $key_1cde = { 48 b6 [2] 3c ae [2] 7b ac [2] 3c bd [2] 72 b1 [2] 7e bb [2] 69 b0 [2] 72 fe [2] 4f }

  condition:
    any of them
}