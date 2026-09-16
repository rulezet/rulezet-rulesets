rule TTP_XOR_MULT_DOSStub_cdc4 {
  strings:
    $key_cdc4 = { 99 ac [2] ed b4 [2] aa b6 [2] ed a7 [2] a3 ab [2] af a1 [2] b8 aa [2] a3 e4 [2] 9e }

  condition:
    any of them
}