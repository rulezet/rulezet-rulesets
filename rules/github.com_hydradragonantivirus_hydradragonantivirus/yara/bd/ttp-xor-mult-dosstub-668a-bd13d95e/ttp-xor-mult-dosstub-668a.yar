rule TTP_XOR_MULT_DOSStub_668a {
  strings:
    $key_668a = { 32 e2 [2] 46 fa [2] 01 f8 [2] 46 e9 [2] 08 e5 [2] 04 ef [2] 13 e4 [2] 08 aa [2] 35 }

  condition:
    any of them
}