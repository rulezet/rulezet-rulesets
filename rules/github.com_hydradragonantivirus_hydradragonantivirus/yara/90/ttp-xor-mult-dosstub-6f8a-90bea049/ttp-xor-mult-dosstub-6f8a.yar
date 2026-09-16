rule TTP_XOR_MULT_DOSStub_6f8a {
  strings:
    $key_6f8a = { 3b e2 [2] 4f fa [2] 08 f8 [2] 4f e9 [2] 01 e5 [2] 0d ef [2] 1a e4 [2] 01 aa [2] 3c }

  condition:
    any of them
}