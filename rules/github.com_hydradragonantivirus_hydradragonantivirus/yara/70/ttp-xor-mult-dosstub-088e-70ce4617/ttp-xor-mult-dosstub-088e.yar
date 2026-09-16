rule TTP_XOR_MULT_DOSStub_088e {
  strings:
    $key_088e = { 5c e6 [2] 28 fe [2] 6f fc [2] 28 ed [2] 66 e1 [2] 6a eb [2] 7d e0 [2] 66 ae [2] 5b }

  condition:
    any of them
}