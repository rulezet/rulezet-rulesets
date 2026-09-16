rule TTP_XOR_MULT_DOSStub_01cf {
  strings:
    $key_01cf = { 55 a7 [2] 21 bf [2] 66 bd [2] 21 ac [2] 6f a0 [2] 63 aa [2] 74 a1 [2] 6f ef [2] 52 }

  condition:
    any of them
}