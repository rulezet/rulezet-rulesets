rule TTP_XOR_MULT_DOSStub_388c {
  strings:
    $key_388c = { 6c e4 [2] 18 fc [2] 5f fe [2] 18 ef [2] 56 e3 [2] 5a e9 [2] 4d e2 [2] 56 ac [2] 6b }

  condition:
    any of them
}