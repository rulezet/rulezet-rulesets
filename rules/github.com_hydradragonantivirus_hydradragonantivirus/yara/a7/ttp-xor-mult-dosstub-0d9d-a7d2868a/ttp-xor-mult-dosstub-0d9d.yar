rule TTP_XOR_MULT_DOSStub_0d9d {
  strings:
    $key_0d9d = { 59 f5 [2] 2d ed [2] 6a ef [2] 2d fe [2] 63 f2 [2] 6f f8 [2] 78 f3 [2] 63 bd [2] 5e }

  condition:
    any of them
}