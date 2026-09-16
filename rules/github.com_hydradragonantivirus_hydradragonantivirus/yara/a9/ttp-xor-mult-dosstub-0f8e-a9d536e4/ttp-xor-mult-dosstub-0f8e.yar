rule TTP_XOR_MULT_DOSStub_0f8e {
  strings:
    $key_0f8e = { 5b e6 [2] 2f fe [2] 68 fc [2] 2f ed [2] 61 e1 [2] 6d eb [2] 7a e0 [2] 61 ae [2] 5c }

  condition:
    any of them
}