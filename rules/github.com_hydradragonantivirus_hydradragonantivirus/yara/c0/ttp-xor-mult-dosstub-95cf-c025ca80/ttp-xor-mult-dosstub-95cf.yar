rule TTP_XOR_MULT_DOSStub_95cf {
  strings:
    $key_95cf = { c1 a7 [2] b5 bf [2] f2 bd [2] b5 ac [2] fb a0 [2] f7 aa [2] e0 a1 [2] fb ef [2] c6 }

  condition:
    any of them
}