rule TTP_XOR_MULT_DOSStub_6cde {
  strings:
    $key_6cde = { 38 b6 [2] 4c ae [2] 0b ac [2] 4c bd [2] 02 b1 [2] 0e bb [2] 19 b0 [2] 02 fe [2] 3f }

  condition:
    any of them
}