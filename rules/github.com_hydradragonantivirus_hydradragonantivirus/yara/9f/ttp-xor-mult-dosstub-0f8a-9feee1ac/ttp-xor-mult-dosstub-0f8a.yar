rule TTP_XOR_MULT_DOSStub_0f8a {
  strings:
    $key_0f8a = { 5b e2 [2] 2f fa [2] 68 f8 [2] 2f e9 [2] 61 e5 [2] 6d ef [2] 7a e4 [2] 61 aa [2] 5c }

  condition:
    any of them
}