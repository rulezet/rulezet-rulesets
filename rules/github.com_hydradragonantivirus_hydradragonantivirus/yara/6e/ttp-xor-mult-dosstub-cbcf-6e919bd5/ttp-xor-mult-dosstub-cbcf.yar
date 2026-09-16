rule TTP_XOR_MULT_DOSStub_cbcf {
  strings:
    $key_cbcf = { 9f a7 [2] eb bf [2] ac bd [2] eb ac [2] a5 a0 [2] a9 aa [2] be a1 [2] a5 ef [2] 98 }

  condition:
    any of them
}