rule TTP_XOR_MULT_DOSStub_1ecf {
  strings:
    $key_1ecf = { 4a a7 [2] 3e bf [2] 79 bd [2] 3e ac [2] 70 a0 [2] 7c aa [2] 6b a1 [2] 70 ef [2] 4d }

  condition:
    any of them
}