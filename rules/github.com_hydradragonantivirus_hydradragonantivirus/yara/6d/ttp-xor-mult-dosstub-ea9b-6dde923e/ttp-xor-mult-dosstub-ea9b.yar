rule TTP_XOR_MULT_DOSStub_ea9b {
  strings:
    $key_ea9b = { be f3 [2] ca eb [2] 8d e9 [2] ca f8 [2] 84 f4 [2] 88 fe [2] 9f f5 [2] 84 bb [2] b9 }

  condition:
    any of them
}