rule TTP_XOR_MULT_DOSStub_6b8a {
  strings:
    $key_6b8a = { 3f e2 [2] 4b fa [2] 0c f8 [2] 4b e9 [2] 05 e5 [2] 09 ef [2] 1e e4 [2] 05 aa [2] 38 }

  condition:
    any of them
}