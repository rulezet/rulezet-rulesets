rule TTP_XOR_MULT_DOSStub_3d8e {
  strings:
    $key_3d8e = { 69 e6 [2] 1d fe [2] 5a fc [2] 1d ed [2] 53 e1 [2] 5f eb [2] 48 e0 [2] 53 ae [2] 6e }

  condition:
    any of them
}