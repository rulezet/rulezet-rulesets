rule TTP_XOR_MULT_DOSStub_5cde {
  strings:
    $key_5cde = { 08 b6 [2] 7c ae [2] 3b ac [2] 7c bd [2] 32 b1 [2] 3e bb [2] 29 b0 [2] 32 fe [2] 0f }

  condition:
    any of them
}