rule TTP_XOR_MULT_DOSStub_37c9 {
  strings:
    $key_37c9 = { 63 a1 [2] 17 b9 [2] 50 bb [2] 17 aa [2] 59 a6 [2] 55 ac [2] 42 a7 [2] 59 e9 [2] 64 }

  condition:
    any of them
}