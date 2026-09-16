rule TTP_XOR_MULT_DOSStub_6f8e {
  strings:
    $key_6f8e = { 3b e6 [2] 4f fe [2] 08 fc [2] 4f ed [2] 01 e1 [2] 0d eb [2] 1a e0 [2] 01 ae [2] 3c }

  condition:
    any of them
}