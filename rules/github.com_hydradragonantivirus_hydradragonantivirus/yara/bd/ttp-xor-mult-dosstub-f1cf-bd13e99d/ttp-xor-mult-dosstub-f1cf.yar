rule TTP_XOR_MULT_DOSStub_f1cf {
  strings:
    $key_f1cf = { a5 a7 [2] d1 bf [2] 96 bd [2] d1 ac [2] 9f a0 [2] 93 aa [2] 84 a1 [2] 9f ef [2] a2 }

  condition:
    any of them
}