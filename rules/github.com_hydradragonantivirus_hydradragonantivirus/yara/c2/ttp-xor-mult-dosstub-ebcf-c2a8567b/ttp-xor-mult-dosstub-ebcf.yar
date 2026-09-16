rule TTP_XOR_MULT_DOSStub_ebcf {
  strings:
    $key_ebcf = { bf a7 [2] cb bf [2] 8c bd [2] cb ac [2] 85 a0 [2] 89 aa [2] 9e a1 [2] 85 ef [2] b8 }

  condition:
    any of them
}