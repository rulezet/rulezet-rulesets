rule TTP_XOR_MULT_DOSStub_eb8a {
  strings:
    $key_eb8a = { bf e2 [2] cb fa [2] 8c f8 [2] cb e9 [2] 85 e5 [2] 89 ef [2] 9e e4 [2] 85 aa [2] b8 }

  condition:
    any of them
}