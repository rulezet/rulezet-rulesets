rule TTP_XOR_MULT_DOSStub_5adc {
  strings:
    $key_5adc = { 0e b4 [2] 7a ac [2] 3d ae [2] 7a bf [2] 34 b3 [2] 38 b9 [2] 2f b2 [2] 34 fc [2] 09 }

  condition:
    any of them
}