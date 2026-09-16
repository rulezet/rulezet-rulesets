rule TTP_XOR_MULT_DOSStub_2bdc {
  strings:
    $key_2bdc = { 7f b4 [2] 0b ac [2] 4c ae [2] 0b bf [2] 45 b3 [2] 49 b9 [2] 5e b2 [2] 45 fc [2] 78 }

  condition:
    any of them
}