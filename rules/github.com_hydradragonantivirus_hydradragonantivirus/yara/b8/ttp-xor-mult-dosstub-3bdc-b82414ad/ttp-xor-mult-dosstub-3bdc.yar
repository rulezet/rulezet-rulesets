rule TTP_XOR_MULT_DOSStub_3bdc {
  strings:
    $key_3bdc = { 6f b4 [2] 1b ac [2] 5c ae [2] 1b bf [2] 55 b3 [2] 59 b9 [2] 4e b2 [2] 55 fc [2] 68 }

  condition:
    any of them
}