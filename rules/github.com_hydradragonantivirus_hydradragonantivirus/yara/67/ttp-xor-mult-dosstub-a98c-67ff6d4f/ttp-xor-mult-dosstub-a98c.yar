rule TTP_XOR_MULT_DOSStub_a98c {
  strings:
    $key_a98c = { fd e4 [2] 89 fc [2] ce fe [2] 89 ef [2] c7 e3 [2] cb e9 [2] dc e2 [2] c7 ac [2] fa }

  condition:
    any of them
}