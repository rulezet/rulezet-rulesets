rule TTP_XOR_MULT_DOSStub_46cf {
  strings:
    $key_46cf = { 12 a7 [2] 66 bf [2] 21 bd [2] 66 ac [2] 28 a0 [2] 24 aa [2] 33 a1 [2] 28 ef [2] 15 }

  condition:
    any of them
}