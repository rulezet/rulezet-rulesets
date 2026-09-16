rule TTP_XOR_MULT_DOSStub_fbdc {
  strings:
    $key_fbdc = { af b4 [2] db ac [2] 9c ae [2] db bf [2] 95 b3 [2] 99 b9 [2] 8e b2 [2] 95 fc [2] a8 }

  condition:
    any of them
}