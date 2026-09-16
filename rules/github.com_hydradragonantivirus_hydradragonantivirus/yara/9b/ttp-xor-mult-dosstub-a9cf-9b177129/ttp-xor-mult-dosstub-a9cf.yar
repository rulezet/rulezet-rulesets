rule TTP_XOR_MULT_DOSStub_a9cf {
  strings:
    $key_a9cf = { fd a7 [2] 89 bf [2] ce bd [2] 89 ac [2] c7 a0 [2] cb aa [2] dc a1 [2] c7 ef [2] fa }

  condition:
    any of them
}