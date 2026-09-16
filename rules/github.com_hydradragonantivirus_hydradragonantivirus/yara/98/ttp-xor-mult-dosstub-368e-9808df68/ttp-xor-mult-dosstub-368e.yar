rule TTP_XOR_MULT_DOSStub_368e {
  strings:
    $key_368e = { 62 e6 [2] 16 fe [2] 51 fc [2] 16 ed [2] 58 e1 [2] 54 eb [2] 43 e0 [2] 58 ae [2] 65 }

  condition:
    any of them
}