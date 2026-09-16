rule TTP_XOR_MULT_DOSStub_4c9d {
  strings:
    $key_4c9d = { 18 f5 [2] 6c ed [2] 2b ef [2] 6c fe [2] 22 f2 [2] 2e f8 [2] 39 f3 [2] 22 bd [2] 1f }

  condition:
    any of them
}