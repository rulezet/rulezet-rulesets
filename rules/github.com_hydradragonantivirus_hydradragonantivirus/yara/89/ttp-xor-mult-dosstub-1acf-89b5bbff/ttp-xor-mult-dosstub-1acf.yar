rule TTP_XOR_MULT_DOSStub_1acf {
  strings:
    $key_1acf = { 4e a7 [2] 3a bf [2] 7d bd [2] 3a ac [2] 74 a0 [2] 78 aa [2] 6f a1 [2] 74 ef [2] 49 }

  condition:
    any of them
}