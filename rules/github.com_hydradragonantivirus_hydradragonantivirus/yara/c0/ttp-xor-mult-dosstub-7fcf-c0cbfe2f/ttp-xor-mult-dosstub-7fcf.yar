rule TTP_XOR_MULT_DOSStub_7fcf {
  strings:
    $key_7fcf = { 2b a7 [2] 5f bf [2] 18 bd [2] 5f ac [2] 11 a0 [2] 1d aa [2] 0a a1 [2] 11 ef [2] 2c }

  condition:
    any of them
}