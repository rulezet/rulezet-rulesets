rule TTP_XOR_MULT_DOSStub_1dc4 {
  strings:
    $key_1dc4 = { 49 ac [2] 3d b4 [2] 7a b6 [2] 3d a7 [2] 73 ab [2] 7f a1 [2] 68 aa [2] 73 e4 [2] 4e }

  condition:
    any of them
}