rule TTP_XOR_MULT_DOSStub_b4cf {
  strings:
    $key_b4cf = { e0 a7 [2] 94 bf [2] d3 bd [2] 94 ac [2] da a0 [2] d6 aa [2] c1 a1 [2] da ef [2] e7 }

  condition:
    any of them
}