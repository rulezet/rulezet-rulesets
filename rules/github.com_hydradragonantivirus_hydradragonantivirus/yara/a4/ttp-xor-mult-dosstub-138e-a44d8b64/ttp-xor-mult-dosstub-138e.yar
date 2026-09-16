rule TTP_XOR_MULT_DOSStub_138e {
  strings:
    $key_138e = { 47 e6 [2] 33 fe [2] 74 fc [2] 33 ed [2] 7d e1 [2] 71 eb [2] 66 e0 [2] 7d ae [2] 40 }

  condition:
    any of them
}