rule TTP_XOR_MULT_DOSStub_08cf {
  strings:
    $key_08cf = { 5c a7 [2] 28 bf [2] 6f bd [2] 28 ac [2] 66 a0 [2] 6a aa [2] 7d a1 [2] 66 ef [2] 5b }

  condition:
    any of them
}