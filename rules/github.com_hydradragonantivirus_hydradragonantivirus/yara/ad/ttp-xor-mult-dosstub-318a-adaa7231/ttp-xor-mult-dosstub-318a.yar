rule TTP_XOR_MULT_DOSStub_318a {
  strings:
    $key_318a = { 65 e2 [2] 11 fa [2] 56 f8 [2] 11 e9 [2] 5f e5 [2] 53 ef [2] 44 e4 [2] 5f aa [2] 62 }

  condition:
    any of them
}