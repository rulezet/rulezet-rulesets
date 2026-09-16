rule TTP_XOR_MULT_DOSStub_7adc {
  strings:
    $key_7adc = { 2e b4 [2] 5a ac [2] 1d ae [2] 5a bf [2] 14 b3 [2] 18 b9 [2] 0f b2 [2] 14 fc [2] 29 }

  condition:
    any of them
}