rule TTP_XOR_MULT_DOSStub_1adc {
  strings:
    $key_1adc = { 4e b4 [2] 3a ac [2] 7d ae [2] 3a bf [2] 74 b3 [2] 78 b9 [2] 6f b2 [2] 74 fc [2] 49 }

  condition:
    any of them
}