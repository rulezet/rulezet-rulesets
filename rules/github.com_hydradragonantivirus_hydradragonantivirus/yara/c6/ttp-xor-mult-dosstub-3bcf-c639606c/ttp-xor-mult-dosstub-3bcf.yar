rule TTP_XOR_MULT_DOSStub_3bcf {
  strings:
    $key_3bcf = { 6f a7 [2] 1b bf [2] 5c bd [2] 1b ac [2] 55 a0 [2] 59 aa [2] 4e a1 [2] 55 ef [2] 68 }

  condition:
    any of them
}