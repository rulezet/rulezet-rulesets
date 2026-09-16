rule TTP_XOR_MULT_DOSStub_58cf {
  strings:
    $key_58cf = { 0c a7 [2] 78 bf [2] 3f bd [2] 78 ac [2] 36 a0 [2] 3a aa [2] 2d a1 [2] 36 ef [2] 0b }

  condition:
    any of them
}