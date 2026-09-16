rule TTP_XOR_MULT_DOSStub_608a {
  strings:
    $key_608a = { 34 e2 [2] 40 fa [2] 07 f8 [2] 40 e9 [2] 0e e5 [2] 02 ef [2] 15 e4 [2] 0e aa [2] 33 }

  condition:
    any of them
}