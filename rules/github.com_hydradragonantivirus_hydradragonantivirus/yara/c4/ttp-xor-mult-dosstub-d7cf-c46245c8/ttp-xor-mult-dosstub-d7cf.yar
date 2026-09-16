rule TTP_XOR_MULT_DOSStub_d7cf {
  strings:
    $key_d7cf = { 83 a7 [2] f7 bf [2] b0 bd [2] f7 ac [2] b9 a0 [2] b5 aa [2] a2 a1 [2] b9 ef [2] 84 }

  condition:
    any of them
}