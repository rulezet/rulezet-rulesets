rule TTP_XOR_MULT_DOSStub_689d {
  strings:
    $key_689d = { 3c f5 [2] 48 ed [2] 0f ef [2] 48 fe [2] 06 f2 [2] 0a f8 [2] 1d f3 [2] 06 bd [2] 3b }

  condition:
    any of them
}