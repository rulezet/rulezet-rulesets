rule TTP_XOR_MULT_DOSStub_b8c9 {
  strings:
    $key_b8c9 = { ec a1 [2] 98 b9 [2] df bb [2] 98 aa [2] d6 a6 [2] da ac [2] cd a7 [2] d6 e9 [2] eb }

  condition:
    any of them
}