rule TTP_XOR_MULT_DOSStub_189d {
  strings:
    $key_189d = { 4c f5 [2] 38 ed [2] 7f ef [2] 38 fe [2] 76 f2 [2] 7a f8 [2] 6d f3 [2] 76 bd [2] 4b }

  condition:
    any of them
}