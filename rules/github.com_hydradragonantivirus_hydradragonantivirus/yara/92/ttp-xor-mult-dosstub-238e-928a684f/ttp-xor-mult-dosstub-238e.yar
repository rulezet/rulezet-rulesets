rule TTP_XOR_MULT_DOSStub_238e {
  strings:
    $key_238e = { 77 e6 [2] 03 fe [2] 44 fc [2] 03 ed [2] 4d e1 [2] 41 eb [2] 56 e0 [2] 4d ae [2] 70 }

  condition:
    any of them
}