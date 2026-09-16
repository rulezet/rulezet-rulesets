rule TTP_XOR_MULT_DOSStub_47cf {
  strings:
    $key_47cf = { 13 a7 [2] 67 bf [2] 20 bd [2] 67 ac [2] 29 a0 [2] 25 aa [2] 32 a1 [2] 29 ef [2] 14 }

  condition:
    any of them
}