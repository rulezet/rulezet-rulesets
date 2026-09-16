rule TTP_XOR_MULT_DOSStub_4f8a {
  strings:
    $key_4f8a = { 1b e2 [2] 6f fa [2] 28 f8 [2] 6f e9 [2] 21 e5 [2] 2d ef [2] 3a e4 [2] 21 aa [2] 1c }

  condition:
    any of them
}