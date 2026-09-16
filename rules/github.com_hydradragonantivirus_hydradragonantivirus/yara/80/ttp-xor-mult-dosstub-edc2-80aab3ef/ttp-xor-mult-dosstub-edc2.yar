rule TTP_XOR_MULT_DOSStub_edc2 {
  strings:
    $key_edc2 = { b9 aa [2] cd b2 [2] 8a b0 [2] cd a1 [2] 83 ad [2] 8f a7 [2] 98 ac [2] 83 e2 [2] be }

  condition:
    any of them
}