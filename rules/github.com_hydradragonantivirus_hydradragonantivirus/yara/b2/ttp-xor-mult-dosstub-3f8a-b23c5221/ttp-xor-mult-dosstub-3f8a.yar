rule TTP_XOR_MULT_DOSStub_3f8a {
  strings:
    $key_3f8a = { 6b e2 [2] 1f fa [2] 58 f8 [2] 1f e9 [2] 51 e5 [2] 5d ef [2] 4a e4 [2] 51 aa [2] 6c }

  condition:
    any of them
}