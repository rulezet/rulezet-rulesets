rule TTP_XOR_MULT_DOSStub_accf {
  strings:
    $key_accf = { f8 a7 [2] 8c bf [2] cb bd [2] 8c ac [2] c2 a0 [2] ce aa [2] d9 a1 [2] c2 ef [2] ff }

  condition:
    any of them
}