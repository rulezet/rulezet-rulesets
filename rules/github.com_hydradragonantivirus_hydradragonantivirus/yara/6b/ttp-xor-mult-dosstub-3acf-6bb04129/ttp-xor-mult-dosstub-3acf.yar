rule TTP_XOR_MULT_DOSStub_3acf {
  strings:
    $key_3acf = { 6e a7 [2] 1a bf [2] 5d bd [2] 1a ac [2] 54 a0 [2] 58 aa [2] 4f a1 [2] 54 ef [2] 69 }

  condition:
    any of them
}