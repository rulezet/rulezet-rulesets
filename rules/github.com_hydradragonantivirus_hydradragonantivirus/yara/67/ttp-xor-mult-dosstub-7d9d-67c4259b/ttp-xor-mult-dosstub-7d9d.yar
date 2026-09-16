rule TTP_XOR_MULT_DOSStub_7d9d {
  strings:
    $key_7d9d = { 29 f5 [2] 5d ed [2] 1a ef [2] 5d fe [2] 13 f2 [2] 1f f8 [2] 08 f3 [2] 13 bd [2] 2e }

  condition:
    any of them
}