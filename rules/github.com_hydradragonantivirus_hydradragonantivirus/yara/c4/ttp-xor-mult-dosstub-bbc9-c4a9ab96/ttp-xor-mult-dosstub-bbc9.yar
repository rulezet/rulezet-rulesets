rule TTP_XOR_MULT_DOSStub_bbc9 {
  strings:
    $key_bbc9 = { ef a1 [2] 9b b9 [2] dc bb [2] 9b aa [2] d5 a6 [2] d9 ac [2] ce a7 [2] d5 e9 [2] e8 }

  condition:
    any of them
}