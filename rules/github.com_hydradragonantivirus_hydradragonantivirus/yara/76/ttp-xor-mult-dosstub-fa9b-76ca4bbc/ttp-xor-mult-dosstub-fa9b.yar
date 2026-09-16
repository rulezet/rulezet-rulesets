rule TTP_XOR_MULT_DOSStub_fa9b {
  strings:
    $key_fa9b = { ae f3 [2] da eb [2] 9d e9 [2] da f8 [2] 94 f4 [2] 98 fe [2] 8f f5 [2] 94 bb [2] a9 }

  condition:
    any of them
}