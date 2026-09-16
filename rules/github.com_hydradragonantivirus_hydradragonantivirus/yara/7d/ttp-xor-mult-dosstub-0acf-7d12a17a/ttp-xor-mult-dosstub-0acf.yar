rule TTP_XOR_MULT_DOSStub_0acf {
  strings:
    $key_0acf = { 5e a7 [2] 2a bf [2] 6d bd [2] 2a ac [2] 64 a0 [2] 68 aa [2] 7f a1 [2] 64 ef [2] 59 }

  condition:
    any of them
}