rule TTP_XOR_MULT_DOSStub_4d9d {
  strings:
    $key_4d9d = { 19 f5 [2] 6d ed [2] 2a ef [2] 6d fe [2] 23 f2 [2] 2f f8 [2] 38 f3 [2] 23 bd [2] 1e }

  condition:
    any of them
}