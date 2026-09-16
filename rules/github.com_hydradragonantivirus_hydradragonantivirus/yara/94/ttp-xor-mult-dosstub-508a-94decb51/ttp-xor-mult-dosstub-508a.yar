rule TTP_XOR_MULT_DOSStub_508a {
  strings:
    $key_508a = { 04 e2 [2] 70 fa [2] 37 f8 [2] 70 e9 [2] 3e e5 [2] 32 ef [2] 25 e4 [2] 3e aa [2] 03 }

  condition:
    any of them
}