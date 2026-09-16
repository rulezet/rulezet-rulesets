rule TTP_XOR_MULT_DOSStub_f08a {
  strings:
    $key_f08a = { a4 e2 [2] d0 fa [2] 97 f8 [2] d0 e9 [2] 9e e5 [2] 92 ef [2] 85 e4 [2] 9e aa [2] a3 }

  condition:
    any of them
}