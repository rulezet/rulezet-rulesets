rule TTP_XOR_MULT_DOSStub_588e {
  strings:
    $key_588e = { 0c e6 [2] 78 fe [2] 3f fc [2] 78 ed [2] 36 e1 [2] 3a eb [2] 2d e0 [2] 36 ae [2] 0b }

  condition:
    any of them
}