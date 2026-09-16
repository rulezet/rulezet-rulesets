rule TTP_XOR_MULT_DOSStub_7acf {
  strings:
    $key_7acf = { 2e a7 [2] 5a bf [2] 1d bd [2] 5a ac [2] 14 a0 [2] 18 aa [2] 0f a1 [2] 14 ef [2] 29 }

  condition:
    any of them
}