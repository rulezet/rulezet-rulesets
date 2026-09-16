rule TTP_XOR_MULT_DOSStub_3f8e {
  strings:
    $key_3f8e = { 6b e6 [2] 1f fe [2] 58 fc [2] 1f ed [2] 51 e1 [2] 5d eb [2] 4a e0 [2] 51 ae [2] 6c }

  condition:
    any of them
}