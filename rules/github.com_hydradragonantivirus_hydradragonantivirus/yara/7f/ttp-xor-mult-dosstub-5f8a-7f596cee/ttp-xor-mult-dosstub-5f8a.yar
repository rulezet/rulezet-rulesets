rule TTP_XOR_MULT_DOSStub_5f8a {
  strings:
    $key_5f8a = { 0b e2 [2] 7f fa [2] 38 f8 [2] 7f e9 [2] 31 e5 [2] 3d ef [2] 2a e4 [2] 31 aa [2] 0c }

  condition:
    any of them
}