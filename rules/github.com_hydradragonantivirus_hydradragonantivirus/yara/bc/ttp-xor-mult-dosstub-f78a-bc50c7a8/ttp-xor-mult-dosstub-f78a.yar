rule TTP_XOR_MULT_DOSStub_f78a {
  strings:
    $key_f78a = { a3 e2 [2] d7 fa [2] 90 f8 [2] d7 e9 [2] 99 e5 [2] 95 ef [2] 82 e4 [2] 99 aa [2] a4 }

  condition:
    any of them
}