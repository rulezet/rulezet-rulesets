rule TTP_XOR_MULT_DOSStub_018a {
  strings:
    $key_018a = { 55 e2 [2] 21 fa [2] 66 f8 [2] 21 e9 [2] 6f e5 [2] 63 ef [2] 74 e4 [2] 6f aa [2] 52 }

  condition:
    any of them
}