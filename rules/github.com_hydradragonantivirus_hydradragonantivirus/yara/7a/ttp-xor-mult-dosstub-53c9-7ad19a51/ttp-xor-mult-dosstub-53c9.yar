rule TTP_XOR_MULT_DOSStub_53c9 {
  strings:
    $key_53c9 = { 07 a1 [2] 73 b9 [2] 34 bb [2] 73 aa [2] 3d a6 [2] 31 ac [2] 26 a7 [2] 3d e9 [2] 00 }

  condition:
    any of them
}