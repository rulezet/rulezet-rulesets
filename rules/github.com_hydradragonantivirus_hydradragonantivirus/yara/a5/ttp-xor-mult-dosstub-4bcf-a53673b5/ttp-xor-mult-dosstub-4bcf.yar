rule TTP_XOR_MULT_DOSStub_4bcf {
  strings:
    $key_4bcf = { 1f a7 [2] 6b bf [2] 2c bd [2] 6b ac [2] 25 a0 [2] 29 aa [2] 3e a1 [2] 25 ef [2] 18 }

  condition:
    any of them
}