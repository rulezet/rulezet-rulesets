rule TTP_XOR_MULT_DOSStub_738e {
  strings:
    $key_738e = { 27 e6 [2] 53 fe [2] 14 fc [2] 53 ed [2] 1d e1 [2] 11 eb [2] 06 e0 [2] 1d ae [2] 20 }

  condition:
    any of them
}