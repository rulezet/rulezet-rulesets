rule TTP_XOR_MULT_DOSStub_fe9d {
  strings:
    $key_fe9d = { aa f5 [2] de ed [2] 99 ef [2] de fe [2] 90 f2 [2] 9c f8 [2] 8b f3 [2] 90 bd [2] ad }

  condition:
    any of them
}