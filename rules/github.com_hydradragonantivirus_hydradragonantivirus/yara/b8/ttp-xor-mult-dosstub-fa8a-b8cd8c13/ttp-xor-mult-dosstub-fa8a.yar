rule TTP_XOR_MULT_DOSStub_fa8a {
  strings:
    $key_fa8a = { ae e2 [2] da fa [2] 9d f8 [2] da e9 [2] 94 e5 [2] 98 ef [2] 8f e4 [2] 94 aa [2] a9 }

  condition:
    any of them
}