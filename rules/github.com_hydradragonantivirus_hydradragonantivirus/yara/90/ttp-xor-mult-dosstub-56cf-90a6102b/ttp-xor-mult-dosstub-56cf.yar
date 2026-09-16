rule TTP_XOR_MULT_DOSStub_56cf {
  strings:
    $key_56cf = { 02 a7 [2] 76 bf [2] 31 bd [2] 76 ac [2] 38 a0 [2] 34 aa [2] 23 a1 [2] 38 ef [2] 05 }

  condition:
    any of them
}