rule TTP_XOR_MULT_DOSStub_218e {
  strings:
    $key_218e = { 75 e6 [2] 01 fe [2] 46 fc [2] 01 ed [2] 4f e1 [2] 43 eb [2] 54 e0 [2] 4f ae [2] 72 }

  condition:
    any of them
}