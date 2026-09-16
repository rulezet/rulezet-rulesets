rule TTP_XOR_MULT_DOSStub_4ecb {
  strings:
    $key_4ecb = { 1a a3 [2] 6e bb [2] 29 b9 [2] 6e a8 [2] 20 a4 [2] 2c ae [2] 3b a5 [2] 20 eb [2] 1d }

  condition:
    any of them
}