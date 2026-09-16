rule TTP_XOR_MULT_DOSStub_a98a {
  strings:
    $key_a98a = { fd e2 [2] 89 fa [2] ce f8 [2] 89 e9 [2] c7 e5 [2] cb ef [2] dc e4 [2] c7 aa [2] fa }

  condition:
    any of them
}