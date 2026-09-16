rule TTP_XOR_MULT_DOSStub_2d9d {
  strings:
    $key_2d9d = { 79 f5 [2] 0d ed [2] 4a ef [2] 0d fe [2] 43 f2 [2] 4f f8 [2] 58 f3 [2] 43 bd [2] 7e }

  condition:
    any of them
}