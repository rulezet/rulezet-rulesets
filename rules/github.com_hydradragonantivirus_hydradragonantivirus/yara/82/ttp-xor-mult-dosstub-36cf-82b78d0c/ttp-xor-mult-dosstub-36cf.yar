rule TTP_XOR_MULT_DOSStub_36cf {
  strings:
    $key_36cf = { 62 a7 [2] 16 bf [2] 51 bd [2] 16 ac [2] 58 a0 [2] 54 aa [2] 43 a1 [2] 58 ef [2] 65 }

  condition:
    any of them
}