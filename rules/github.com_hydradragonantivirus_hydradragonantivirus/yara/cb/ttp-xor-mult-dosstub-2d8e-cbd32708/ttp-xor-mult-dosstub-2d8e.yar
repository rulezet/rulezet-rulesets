rule TTP_XOR_MULT_DOSStub_2d8e {
  strings:
    $key_2d8e = { 79 e6 [2] 0d fe [2] 4a fc [2] 0d ed [2] 43 e1 [2] 4f eb [2] 58 e0 [2] 43 ae [2] 7e }

  condition:
    any of them
}