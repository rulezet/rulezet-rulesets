rule TTP_XOR_MULT_DOSStub_dd9b {
  strings:
    $key_dd9b = { 89 f3 [2] fd eb [2] ba e9 [2] fd f8 [2] b3 f4 [2] bf fe [2] a8 f5 [2] b3 bb [2] 8e }

  condition:
    any of them
}