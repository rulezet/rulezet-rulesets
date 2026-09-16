rule TTP_XOR_MULT_DOSStub_abc9 {
  strings:
    $key_abc9 = { ff a1 [2] 8b b9 [2] cc bb [2] 8b aa [2] c5 a6 [2] c9 ac [2] de a7 [2] c5 e9 [2] f8 }

  condition:
    any of them
}