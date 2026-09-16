rule TTP_XOR_MULT_DOSStub_76cf {
  strings:
    $key_76cf = { 22 a7 [2] 56 bf [2] 11 bd [2] 56 ac [2] 18 a0 [2] 14 aa [2] 03 a1 [2] 18 ef [2] 25 }

  condition:
    any of them
}