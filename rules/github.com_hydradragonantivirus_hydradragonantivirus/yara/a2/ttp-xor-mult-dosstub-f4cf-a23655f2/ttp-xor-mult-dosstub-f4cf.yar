rule TTP_XOR_MULT_DOSStub_f4cf {
  strings:
    $key_f4cf = { a0 a7 [2] d4 bf [2] 93 bd [2] d4 ac [2] 9a a0 [2] 96 aa [2] 81 a1 [2] 9a ef [2] a7 }

  condition:
    any of them
}