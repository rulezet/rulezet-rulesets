rule TTP_XOR_MULT_DOSStub_38cf {
  strings:
    $key_38cf = { 6c a7 [2] 18 bf [2] 5f bd [2] 18 ac [2] 56 a0 [2] 5a aa [2] 4d a1 [2] 56 ef [2] 6b }

  condition:
    any of them
}