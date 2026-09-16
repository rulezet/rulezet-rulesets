rule TTP_XOR_MULT_DOSStub_259b {
  strings:
    $key_259b = { 71 f3 [2] 05 eb [2] 42 e9 [2] 05 f8 [2] 4b f4 [2] 47 fe [2] 50 f5 [2] 4b bb [2] 76 }

  condition:
    any of them
}