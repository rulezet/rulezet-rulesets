rule TTP_XOR_MULT_DOSStub_edc4 {
  strings:
    $key_edc4 = { b9 ac [2] cd b4 [2] 8a b6 [2] cd a7 [2] 83 ab [2] 8f a1 [2] 98 aa [2] 83 e4 [2] be }

  condition:
    any of them
}