rule TTP_XOR_MULT_DOSStub_e49b {
  strings:
    $key_e49b = { b0 f3 [2] c4 eb [2] 83 e9 [2] c4 f8 [2] 8a f4 [2] 86 fe [2] 91 f5 [2] 8a bb [2] b7 }

  condition:
    any of them
}