rule TTP_XOR_MULT_DOSStub_218a {
  strings:
    $key_218a = { 75 e2 [2] 01 fa [2] 46 f8 [2] 01 e9 [2] 4f e5 [2] 43 ef [2] 54 e4 [2] 4f aa [2] 72 }

  condition:
    any of them
}