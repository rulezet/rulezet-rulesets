rule TTP_XOR_MULT_DOSStub_60cf {
  strings:
    $key_60cf = { 34 a7 [2] 40 bf [2] 07 bd [2] 40 ac [2] 0e a0 [2] 02 aa [2] 15 a1 [2] 0e ef [2] 33 }

  condition:
    any of them
}