rule TTP_XOR_MULT_DOSStub_05cf {
  strings:
    $key_05cf = { 51 a7 [2] 25 bf [2] 62 bd [2] 25 ac [2] 6b a0 [2] 67 aa [2] 70 a1 [2] 6b ef [2] 56 }

  condition:
    any of them
}