rule TTP_XOR_MULT_DOSStub_718e {
  strings:
    $key_718e = { 25 e6 [2] 51 fe [2] 16 fc [2] 51 ed [2] 1f e1 [2] 13 eb [2] 04 e0 [2] 1f ae [2] 22 }

  condition:
    any of them
}