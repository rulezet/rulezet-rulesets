rule TTP_XOR_MULT_DOSStub_3dcf {
  strings:
    $key_3dcf = { 69 a7 [2] 1d bf [2] 5a bd [2] 1d ac [2] 53 a0 [2] 5f aa [2] 48 a1 [2] 53 ef [2] 6e }

  condition:
    any of them
}