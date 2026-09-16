rule TTP_XOR_MULT_DOSStub_24de {
  strings:
    $key_24de = { 70 b6 [2] 04 ae [2] 43 ac [2] 04 bd [2] 4a b1 [2] 46 bb [2] 51 b0 [2] 4a fe [2] 77 }

  condition:
    any of them
}