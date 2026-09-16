rule TTP_XOR_MULT_DOSStub_5f8e {
  strings:
    $key_5f8e = { 0b e6 [2] 7f fe [2] 38 fc [2] 7f ed [2] 31 e1 [2] 3d eb [2] 2a e0 [2] 31 ae [2] 0c }

  condition:
    any of them
}