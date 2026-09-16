rule TTP_XOR_MULT_DOSStub_cbdc {
  strings:
    $key_cbdc = { 9f b4 [2] eb ac [2] ac ae [2] eb bf [2] a5 b3 [2] a9 b9 [2] be b2 [2] a5 fc [2] 98 }

  condition:
    any of them
}