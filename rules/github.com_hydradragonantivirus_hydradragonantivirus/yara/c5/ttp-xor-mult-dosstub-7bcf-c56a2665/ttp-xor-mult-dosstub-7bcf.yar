rule TTP_XOR_MULT_DOSStub_7bcf {
  strings:
    $key_7bcf = { 2f a7 [2] 5b bf [2] 1c bd [2] 5b ac [2] 15 a0 [2] 19 aa [2] 0e a1 [2] 15 ef [2] 28 }

  condition:
    any of them
}