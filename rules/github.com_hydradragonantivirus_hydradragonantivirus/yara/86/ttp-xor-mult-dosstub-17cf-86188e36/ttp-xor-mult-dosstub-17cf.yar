rule TTP_XOR_MULT_DOSStub_17cf {
  strings:
    $key_17cf = { 43 a7 [2] 37 bf [2] 70 bd [2] 37 ac [2] 79 a0 [2] 75 aa [2] 62 a1 [2] 79 ef [2] 44 }

  condition:
    any of them
}