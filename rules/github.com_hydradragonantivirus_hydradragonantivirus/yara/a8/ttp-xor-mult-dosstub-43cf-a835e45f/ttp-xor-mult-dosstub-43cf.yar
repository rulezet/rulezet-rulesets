rule TTP_XOR_MULT_DOSStub_43cf {
  strings:
    $key_43cf = { 17 a7 [2] 63 bf [2] 24 bd [2] 63 ac [2] 2d a0 [2] 21 aa [2] 36 a1 [2] 2d ef [2] 10 }

  condition:
    any of them
}