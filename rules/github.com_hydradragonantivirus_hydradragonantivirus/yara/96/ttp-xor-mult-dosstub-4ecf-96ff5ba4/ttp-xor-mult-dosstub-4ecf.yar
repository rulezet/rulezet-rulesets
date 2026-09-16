rule TTP_XOR_MULT_DOSStub_4ecf {
  strings:
    $key_4ecf = { 1a a7 [2] 6e bf [2] 29 bd [2] 6e ac [2] 20 a0 [2] 2c aa [2] 3b a1 [2] 20 ef [2] 1d }

  condition:
    any of them
}