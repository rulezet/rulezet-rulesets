rule TTP_XOR_MULT_DOSStub_6d9d {
  strings:
    $key_6d9d = { 39 f5 [2] 4d ed [2] 0a ef [2] 4d fe [2] 03 f2 [2] 0f f8 [2] 18 f3 [2] 03 bd [2] 3e }

  condition:
    any of them
}