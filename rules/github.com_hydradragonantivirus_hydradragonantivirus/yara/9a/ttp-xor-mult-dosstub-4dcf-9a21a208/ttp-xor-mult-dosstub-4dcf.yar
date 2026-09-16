rule TTP_XOR_MULT_DOSStub_4dcf {
  strings:
    $key_4dcf = { 19 a7 [2] 6d bf [2] 2a bd [2] 6d ac [2] 23 a0 [2] 2f aa [2] 38 a1 [2] 23 ef [2] 1e }

  condition:
    any of them
}