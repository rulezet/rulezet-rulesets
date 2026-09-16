rule TTP_XOR_MULT_DOSStub_7bdc {
  strings:
    $key_7bdc = { 2f b4 [2] 5b ac [2] 1c ae [2] 5b bf [2] 15 b3 [2] 19 b9 [2] 0e b2 [2] 15 fc [2] 28 }

  condition:
    any of them
}