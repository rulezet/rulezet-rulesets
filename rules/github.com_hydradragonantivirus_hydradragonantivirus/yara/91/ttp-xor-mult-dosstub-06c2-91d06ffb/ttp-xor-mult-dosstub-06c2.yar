rule TTP_XOR_MULT_DOSStub_06c2 {
  strings:
    $key_06c2 = { 52 aa [2] 26 b2 [2] 61 b0 [2] 26 a1 [2] 68 ad [2] 64 a7 [2] 73 ac [2] 68 e2 [2] 55 }

  condition:
    any of them
}