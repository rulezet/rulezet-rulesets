rule TTP_XOR_MULT_DOSStub_4e9d {
  strings:
    $key_4e9d = { 1a f5 [2] 6e ed [2] 29 ef [2] 6e fe [2] 20 f2 [2] 2c f8 [2] 3b f3 [2] 20 bd [2] 1d }

  condition:
    any of them
}