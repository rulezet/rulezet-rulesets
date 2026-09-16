rule TTP_XOR_MULT_DOSStub_0e8e {
  strings:
    $key_0e8e = { 5a e6 [2] 2e fe [2] 69 fc [2] 2e ed [2] 60 e1 [2] 6c eb [2] 7b e0 [2] 60 ae [2] 5d }

  condition:
    any of them
}