rule TTP_XOR_MULT_DOSStub_669b {
  strings:
    $key_669b = { 32 f3 [2] 46 eb [2] 01 e9 [2] 46 f8 [2] 08 f4 [2] 04 fe [2] 13 f5 [2] 08 bb [2] 35 }

  condition:
    any of them
}