rule TTP_XOR_MULT_DOSStub_3ecf {
  strings:
    $key_3ecf = { 6a a7 [2] 1e bf [2] 59 bd [2] 1e ac [2] 50 a0 [2] 5c aa [2] 4b a1 [2] 50 ef [2] 6d }

  condition:
    any of them
}