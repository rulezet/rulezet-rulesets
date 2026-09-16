rule TTP_XOR_MULT_DOSStub_ac9b {
  strings:
    $key_ac9b = { f8 f3 [2] 8c eb [2] cb e9 [2] 8c f8 [2] c2 f4 [2] ce fe [2] d9 f5 [2] c2 bb [2] ff }

  condition:
    any of them
}