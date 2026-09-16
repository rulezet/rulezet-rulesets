rule TTP_XOR_MULT_DOSStub_62cf {
  strings:
    $key_62cf = { 36 a7 [2] 42 bf [2] 05 bd [2] 42 ac [2] 0c a0 [2] 00 aa [2] 17 a1 [2] 0c ef [2] 31 }

  condition:
    any of them
}