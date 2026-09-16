rule TTP_XOR_MULT_DOSStub_97cf {
  strings:
    $key_97cf = { c3 a7 [2] b7 bf [2] f0 bd [2] b7 ac [2] f9 a0 [2] f5 aa [2] e2 a1 [2] f9 ef [2] c4 }

  condition:
    any of them
}