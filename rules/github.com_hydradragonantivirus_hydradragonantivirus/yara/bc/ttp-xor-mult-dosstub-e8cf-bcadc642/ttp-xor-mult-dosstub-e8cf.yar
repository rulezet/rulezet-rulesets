rule TTP_XOR_MULT_DOSStub_e8cf {
  strings:
    $key_e8cf = { bc a7 [2] c8 bf [2] 8f bd [2] c8 ac [2] 86 a0 [2] 8a aa [2] 9d a1 [2] 86 ef [2] bb }

  condition:
    any of them
}