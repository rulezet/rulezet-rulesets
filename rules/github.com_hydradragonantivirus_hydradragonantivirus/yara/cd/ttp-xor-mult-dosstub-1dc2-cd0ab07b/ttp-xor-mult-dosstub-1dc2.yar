rule TTP_XOR_MULT_DOSStub_1dc2 {
  strings:
    $key_1dc2 = { 49 aa [2] 3d b2 [2] 7a b0 [2] 3d a1 [2] 73 ad [2] 7f a7 [2] 68 ac [2] 73 e2 [2] 4e }

  condition:
    any of them
}