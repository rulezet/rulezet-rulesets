rule TTP_XOR_MULT_DOSStub_eecf {
  strings:
    $key_eecf = { ba a7 [2] ce bf [2] 89 bd [2] ce ac [2] 80 a0 [2] 8c aa [2] 9b a1 [2] 80 ef [2] bd }

  condition:
    any of them
}