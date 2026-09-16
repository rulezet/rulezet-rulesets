rule TTP_XOR_MULT_DOSStub_c6cf {
  strings:
    $key_c6cf = { 92 a7 [2] e6 bf [2] a1 bd [2] e6 ac [2] a8 a0 [2] a4 aa [2] b3 a1 [2] a8 ef [2] 95 }

  condition:
    any of them
}