rule TTP_XOR_MULT_DOSStub_f0cf {
  strings:
    $key_f0cf = { a4 a7 [2] d0 bf [2] 97 bd [2] d0 ac [2] 9e a0 [2] 92 aa [2] 85 a1 [2] 9e ef [2] a3 }

  condition:
    any of them
}