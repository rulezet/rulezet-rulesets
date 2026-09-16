rule TTP_XOR_MULT_DOSStub_51cf {
  strings:
    $key_51cf = { 05 a7 [2] 71 bf [2] 36 bd [2] 71 ac [2] 3f a0 [2] 33 aa [2] 24 a1 [2] 3f ef [2] 02 }

  condition:
    any of them
}