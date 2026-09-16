rule TTP_XOR_MULT_DOSStub_aadc {
  strings:
    $key_aadc = { fe b4 [2] 8a ac [2] cd ae [2] 8a bf [2] c4 b3 [2] c8 b9 [2] df b2 [2] c4 fc [2] f9 }

  condition:
    any of them
}