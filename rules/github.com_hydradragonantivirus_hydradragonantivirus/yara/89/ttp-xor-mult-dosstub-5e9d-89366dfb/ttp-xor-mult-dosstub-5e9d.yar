rule TTP_XOR_MULT_DOSStub_5e9d {
  strings:
    $key_5e9d = { 0a f5 [2] 7e ed [2] 39 ef [2] 7e fe [2] 30 f2 [2] 3c f8 [2] 2b f3 [2] 30 bd [2] 0d }

  condition:
    any of them
}