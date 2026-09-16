rule TTP_XOR_MULT_DOSStub_308a {
  strings:
    $key_308a = { 64 e2 [2] 10 fa [2] 57 f8 [2] 10 e9 [2] 5e e5 [2] 52 ef [2] 45 e4 [2] 5e aa [2] 63 }

  condition:
    any of them
}