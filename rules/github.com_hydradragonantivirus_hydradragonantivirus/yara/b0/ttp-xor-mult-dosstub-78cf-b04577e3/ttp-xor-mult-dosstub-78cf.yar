rule TTP_XOR_MULT_DOSStub_78cf {
  strings:
    $key_78cf = { 2c a7 [2] 58 bf [2] 1f bd [2] 58 ac [2] 16 a0 [2] 1a aa [2] 0d a1 [2] 16 ef [2] 2b }

  condition:
    any of them
}