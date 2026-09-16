rule TTP_XOR_MULT_DOSStub_1cdc {
  strings:
    $key_1cdc = { 48 b4 [2] 3c ac [2] 7b ae [2] 3c bf [2] 72 b3 [2] 7e b9 [2] 69 b2 [2] 72 fc [2] 4f }

  condition:
    any of them
}