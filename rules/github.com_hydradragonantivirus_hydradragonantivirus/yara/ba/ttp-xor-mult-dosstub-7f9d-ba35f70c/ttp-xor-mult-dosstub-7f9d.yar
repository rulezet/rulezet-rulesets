rule TTP_XOR_MULT_DOSStub_7f9d {
  strings:
    $key_7f9d = { 2b f5 [2] 5f ed [2] 18 ef [2] 5f fe [2] 11 f2 [2] 1d f8 [2] 0a f3 [2] 11 bd [2] 2c }

  condition:
    any of them
}