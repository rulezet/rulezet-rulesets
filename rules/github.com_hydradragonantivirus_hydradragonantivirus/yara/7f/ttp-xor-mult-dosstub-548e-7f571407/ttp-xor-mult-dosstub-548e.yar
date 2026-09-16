rule TTP_XOR_MULT_DOSStub_548e {
  strings:
    $key_548e = { 00 e6 [2] 74 fe [2] 33 fc [2] 74 ed [2] 3a e1 [2] 36 eb [2] 21 e0 [2] 3a ae [2] 07 }

  condition:
    any of them
}