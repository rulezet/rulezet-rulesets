rule TTP_XOR_MULT_DOSStub_6dcf {
  strings:
    $key_6dcf = { 39 a7 [2] 4d bf [2] 0a bd [2] 4d ac [2] 03 a0 [2] 0f aa [2] 18 a1 [2] 03 ef [2] 3e }

  condition:
    any of them
}