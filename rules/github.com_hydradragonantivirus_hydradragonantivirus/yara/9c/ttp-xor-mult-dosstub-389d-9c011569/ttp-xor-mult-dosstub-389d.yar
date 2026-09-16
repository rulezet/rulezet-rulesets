rule TTP_XOR_MULT_DOSStub_389d {
  strings:
    $key_389d = { 6c f5 [2] 18 ed [2] 5f ef [2] 18 fe [2] 56 f2 [2] 5a f8 [2] 4d f3 [2] 56 bd [2] 6b }

  condition:
    any of them
}