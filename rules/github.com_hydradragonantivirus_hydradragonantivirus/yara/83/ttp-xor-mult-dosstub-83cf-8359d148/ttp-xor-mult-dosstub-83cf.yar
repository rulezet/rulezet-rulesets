rule TTP_XOR_MULT_DOSStub_83cf {
  strings:
    $key_83cf = { d7 a7 [2] a3 bf [2] e4 bd [2] a3 ac [2] ed a0 [2] e1 aa [2] f6 a1 [2] ed ef [2] d0 }

  condition:
    any of them
}