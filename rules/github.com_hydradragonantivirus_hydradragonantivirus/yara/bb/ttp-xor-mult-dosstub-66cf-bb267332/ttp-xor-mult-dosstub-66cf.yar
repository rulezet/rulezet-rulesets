rule TTP_XOR_MULT_DOSStub_66cf {
  strings:
    $key_66cf = { 32 a7 [2] 46 bf [2] 01 bd [2] 46 ac [2] 08 a0 [2] 04 aa [2] 13 a1 [2] 08 ef [2] 35 }

  condition:
    any of them
}