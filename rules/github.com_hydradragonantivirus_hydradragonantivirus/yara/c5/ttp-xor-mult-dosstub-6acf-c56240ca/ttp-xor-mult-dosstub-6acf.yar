rule TTP_XOR_MULT_DOSStub_6acf {
  strings:
    $key_6acf = { 3e a7 [2] 4a bf [2] 0d bd [2] 4a ac [2] 04 a0 [2] 08 aa [2] 1f a1 [2] 04 ef [2] 39 }

  condition:
    any of them
}