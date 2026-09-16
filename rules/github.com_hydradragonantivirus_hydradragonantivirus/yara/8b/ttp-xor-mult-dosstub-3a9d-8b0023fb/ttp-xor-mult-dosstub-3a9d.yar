rule TTP_XOR_MULT_DOSStub_3a9d {
  strings:
    $key_3a9d = { 6e f5 [2] 1a ed [2] 5d ef [2] 1a fe [2] 54 f2 [2] 58 f8 [2] 4f f3 [2] 54 bd [2] 69 }

  condition:
    any of them
}