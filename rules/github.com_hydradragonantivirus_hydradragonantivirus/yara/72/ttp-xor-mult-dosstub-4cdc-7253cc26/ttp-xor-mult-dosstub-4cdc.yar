rule TTP_XOR_MULT_DOSStub_4cdc {
  strings:
    $key_4cdc = { 18 b4 [2] 6c ac [2] 2b ae [2] 6c bf [2] 22 b3 [2] 2e b9 [2] 39 b2 [2] 22 fc [2] 1f }

  condition:
    any of them
}