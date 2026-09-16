rule TTP_XOR_MULT_DOSStub_31cf {
  strings:
    $key_31cf = { 65 a7 [2] 11 bf [2] 56 bd [2] 11 ac [2] 5f a0 [2] 53 aa [2] 44 a1 [2] 5f ef [2] 62 }

  condition:
    any of them
}