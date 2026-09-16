rule TTP_XOR_MULT_DOSStub_618a {
  strings:
    $key_618a = { 35 e2 [2] 41 fa [2] 06 f8 [2] 41 e9 [2] 0f e5 [2] 03 ef [2] 14 e4 [2] 0f aa [2] 32 }

  condition:
    any of them
}