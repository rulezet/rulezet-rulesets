rule TTP_XOR_MULT_DOSStub_35cf {
  strings:
    $key_35cf = { 61 a7 [2] 15 bf [2] 52 bd [2] 15 ac [2] 5b a0 [2] 57 aa [2] 40 a1 [2] 5b ef [2] 66 }

  condition:
    any of them
}