rule TTP_XOR_MULT_DOSStub_2adc {
  strings:
    $key_2adc = { 7e b4 [2] 0a ac [2] 4d ae [2] 0a bf [2] 44 b3 [2] 48 b9 [2] 5f b2 [2] 44 fc [2] 79 }

  condition:
    any of them
}