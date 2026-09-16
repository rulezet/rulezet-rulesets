rule TTP_XOR_MULT_DOSStub_72cf {
  strings:
    $key_72cf = { 26 a7 [2] 52 bf [2] 15 bd [2] 52 ac [2] 1c a0 [2] 10 aa [2] 07 a1 [2] 1c ef [2] 21 }

  condition:
    any of them
}