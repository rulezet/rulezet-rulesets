rule TTP_XOR_MULT_DOSStub_e5cf {
  strings:
    $key_e5cf = { b1 a7 [2] c5 bf [2] 82 bd [2] c5 ac [2] 8b a0 [2] 87 aa [2] 90 a1 [2] 8b ef [2] b6 }

  condition:
    any of them
}