rule TTP_XOR_MULT_DOSStub_71cf {
  strings:
    $key_71cf = { 25 a7 [2] 51 bf [2] 16 bd [2] 51 ac [2] 1f a0 [2] 13 aa [2] 04 a1 [2] 1f ef [2] 22 }

  condition:
    any of them
}