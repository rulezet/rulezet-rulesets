rule TTP_XOR_MULT_DOSStub_2c9d {
  strings:
    $key_2c9d = { 78 f5 [2] 0c ed [2] 4b ef [2] 0c fe [2] 42 f2 [2] 4e f8 [2] 59 f3 [2] 42 bd [2] 7f }

  condition:
    any of them
}