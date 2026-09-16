rule TTP_XOR_MULT_DOSStub_249b {
  strings:
    $key_249b = { 70 f3 [2] 04 eb [2] 43 e9 [2] 04 f8 [2] 4a f4 [2] 46 fe [2] 51 f5 [2] 4a bb [2] 77 }

  condition:
    any of them
}