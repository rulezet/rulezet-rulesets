rule TTP_XOR_MULT_DOSStub_438e {
  strings:
    $key_438e = { 17 e6 [2] 63 fe [2] 24 fc [2] 63 ed [2] 2d e1 [2] 21 eb [2] 36 e0 [2] 2d ae [2] 10 }

  condition:
    any of them
}