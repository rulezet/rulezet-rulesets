rule TTP_XOR_MULT_DOSStub_e2cf {
  strings:
    $key_e2cf = { b6 a7 [2] c2 bf [2] 85 bd [2] c2 ac [2] 8c a0 [2] 80 aa [2] 97 a1 [2] 8c ef [2] b1 }

  condition:
    any of them
}