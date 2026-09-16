rule TTP_XOR_MULT_DOSStub_96cf {
  strings:
    $key_96cf = { c2 a7 [2] b6 bf [2] f1 bd [2] b6 ac [2] f8 a0 [2] f4 aa [2] e3 a1 [2] f8 ef [2] c5 }

  condition:
    any of them
}