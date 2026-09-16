rule TTP_XOR_MULT_DOSStub_0bcf {
  strings:
    $key_0bcf = { 5f a7 [2] 2b bf [2] 6c bd [2] 2b ac [2] 65 a0 [2] 69 aa [2] 7e a1 [2] 65 ef [2] 58 }

  condition:
    any of them
}