rule TTP_XOR_MULT_DOSStub_488e {
  strings:
    $key_488e = { 1c e6 [2] 68 fe [2] 2f fc [2] 68 ed [2] 26 e1 [2] 2a eb [2] 3d e0 [2] 26 ae [2] 1b }

  condition:
    any of them
}