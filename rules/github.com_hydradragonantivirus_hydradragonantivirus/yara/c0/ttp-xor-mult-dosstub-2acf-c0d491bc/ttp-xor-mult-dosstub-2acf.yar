rule TTP_XOR_MULT_DOSStub_2acf {
  strings:
    $key_2acf = { 7e a7 [2] 0a bf [2] 4d bd [2] 0a ac [2] 44 a0 [2] 48 aa [2] 5f a1 [2] 44 ef [2] 79 }

  condition:
    any of them
}