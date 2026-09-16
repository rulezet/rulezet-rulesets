rule TTP_XOR_MULT_DOSStub_91cf {
  strings:
    $key_91cf = { c5 a7 [2] b1 bf [2] f6 bd [2] b1 ac [2] ff a0 [2] f3 aa [2] e4 a1 [2] ff ef [2] c2 }

  condition:
    any of them
}