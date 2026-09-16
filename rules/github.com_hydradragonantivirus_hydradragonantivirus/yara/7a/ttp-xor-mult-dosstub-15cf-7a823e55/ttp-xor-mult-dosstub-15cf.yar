rule TTP_XOR_MULT_DOSStub_15cf {
  strings:
    $key_15cf = { 41 a7 [2] 35 bf [2] 72 bd [2] 35 ac [2] 7b a0 [2] 77 aa [2] 60 a1 [2] 7b ef [2] 46 }

  condition:
    any of them
}