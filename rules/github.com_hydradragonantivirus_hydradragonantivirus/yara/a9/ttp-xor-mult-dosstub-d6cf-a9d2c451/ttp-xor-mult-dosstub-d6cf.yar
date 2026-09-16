rule TTP_XOR_MULT_DOSStub_d6cf {
  strings:
    $key_d6cf = { 82 a7 [2] f6 bf [2] b1 bd [2] f6 ac [2] b8 a0 [2] b4 aa [2] a3 a1 [2] b8 ef [2] 85 }

  condition:
    any of them
}