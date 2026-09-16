rule TTP_XOR_MULT_DOSStub_64cf {
  strings:
    $key_64cf = { 30 a7 [2] 44 bf [2] 03 bd [2] 44 ac [2] 0a a0 [2] 06 aa [2] 11 a1 [2] 0a ef [2] 37 }

  condition:
    any of them
}