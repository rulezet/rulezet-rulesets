rule TTP_XOR_MULT_DOSStub_f2cf {
  strings:
    $key_f2cf = { a6 a7 [2] d2 bf [2] 95 bd [2] d2 ac [2] 9c a0 [2] 90 aa [2] 87 a1 [2] 9c ef [2] a1 }

  condition:
    any of them
}