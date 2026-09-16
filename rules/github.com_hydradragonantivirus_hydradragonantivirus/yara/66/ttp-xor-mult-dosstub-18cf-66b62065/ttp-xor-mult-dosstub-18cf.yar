rule TTP_XOR_MULT_DOSStub_18cf {
  strings:
    $key_18cf = { 4c a7 [2] 38 bf [2] 7f bd [2] 38 ac [2] 76 a0 [2] 7a aa [2] 6d a1 [2] 76 ef [2] 4b }

  condition:
    any of them
}