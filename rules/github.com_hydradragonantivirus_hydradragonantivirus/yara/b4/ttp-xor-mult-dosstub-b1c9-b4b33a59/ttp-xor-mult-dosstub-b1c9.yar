rule TTP_XOR_MULT_DOSStub_b1c9 {
  strings:
    $key_b1c9 = { e5 a1 [2] 91 b9 [2] d6 bb [2] 91 aa [2] df a6 [2] d3 ac [2] c4 a7 [2] df e9 [2] e2 }

  condition:
    any of them
}