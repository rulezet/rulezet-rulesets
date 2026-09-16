rule TTP_XOR_MULT_DOSStub_1d9d {
  strings:
    $key_1d9d = { 49 f5 [2] 3d ed [2] 7a ef [2] 3d fe [2] 73 f2 [2] 7f f8 [2] 68 f3 [2] 73 bd [2] 4e }

  condition:
    any of them
}