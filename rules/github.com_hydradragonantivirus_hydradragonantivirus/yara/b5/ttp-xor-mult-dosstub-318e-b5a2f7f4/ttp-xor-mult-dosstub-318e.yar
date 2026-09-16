rule TTP_XOR_MULT_DOSStub_318e {
  strings:
    $key_318e = { 65 e6 [2] 11 fe [2] 56 fc [2] 11 ed [2] 5f e1 [2] 53 eb [2] 44 e0 [2] 5f ae [2] 62 }

  condition:
    any of them
}