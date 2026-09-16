rule TTP_XOR_MULT_DOSStub_00cf {
  strings:
    $key_00cf = { 54 a7 [2] 20 bf [2] 67 bd [2] 20 ac [2] 6e a0 [2] 62 aa [2] 75 a1 [2] 6e ef [2] 53 }

  condition:
    any of them
}