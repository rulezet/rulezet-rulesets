rule TTP_XOR_MULT_DOSStub_57c4 {
  strings:
    $key_57c4 = { 03 ac [2] 77 b4 [2] 30 b6 [2] 77 a7 [2] 39 ab [2] 35 a1 [2] 22 aa [2] 39 e4 [2] 04 }

  condition:
    any of them
}