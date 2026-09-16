rule TTP_XOR_MULT_DOSStub_a3cf {
  strings:
    $key_a3cf = { f7 a7 [2] 83 bf [2] c4 bd [2] 83 ac [2] cd a0 [2] c1 aa [2] d6 a1 [2] cd ef [2] f0 }

  condition:
    any of them
}