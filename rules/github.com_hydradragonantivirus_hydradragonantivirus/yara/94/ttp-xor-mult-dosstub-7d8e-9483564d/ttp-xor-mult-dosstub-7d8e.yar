rule TTP_XOR_MULT_DOSStub_7d8e {
  strings:
    $key_7d8e = { 29 e6 [2] 5d fe [2] 1a fc [2] 5d ed [2] 13 e1 [2] 1f eb [2] 08 e0 [2] 13 ae [2] 2e }

  condition:
    any of them
}