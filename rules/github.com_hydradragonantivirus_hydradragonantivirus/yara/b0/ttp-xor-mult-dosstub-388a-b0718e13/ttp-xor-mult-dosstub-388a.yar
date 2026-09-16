rule TTP_XOR_MULT_DOSStub_388a {
  strings:
    $key_388a = { 6c e2 [2] 18 fa [2] 5f f8 [2] 18 e9 [2] 56 e5 [2] 5a ef [2] 4d e4 [2] 56 aa [2] 6b }

  condition:
    any of them
}