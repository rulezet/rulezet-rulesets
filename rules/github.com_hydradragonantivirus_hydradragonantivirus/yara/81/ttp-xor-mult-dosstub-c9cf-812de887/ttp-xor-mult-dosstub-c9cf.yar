rule TTP_XOR_MULT_DOSStub_c9cf {
  strings:
    $key_c9cf = { 9d a7 [2] e9 bf [2] ae bd [2] e9 ac [2] a7 a0 [2] ab aa [2] bc a1 [2] a7 ef [2] 9a }

  condition:
    any of them
}