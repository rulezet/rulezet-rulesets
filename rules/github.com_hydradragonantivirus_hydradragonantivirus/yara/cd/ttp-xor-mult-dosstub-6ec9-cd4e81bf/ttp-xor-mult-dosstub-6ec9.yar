rule TTP_XOR_MULT_DOSStub_6ec9 {
  strings:
    $key_6ec9 = { 3a a1 [2] 4e b9 [2] 09 bb [2] 4e aa [2] 00 a6 [2] 0c ac [2] 1b a7 [2] 00 e9 [2] 3d }

  condition:
    any of them
}