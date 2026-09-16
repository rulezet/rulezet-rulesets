rule TTP_XOR_MULT_DOSStub_40cf {
  strings:
    $key_40cf = { 14 a7 [2] 60 bf [2] 27 bd [2] 60 ac [2] 2e a0 [2] 22 aa [2] 35 a1 [2] 2e ef [2] 13 }

  condition:
    any of them
}