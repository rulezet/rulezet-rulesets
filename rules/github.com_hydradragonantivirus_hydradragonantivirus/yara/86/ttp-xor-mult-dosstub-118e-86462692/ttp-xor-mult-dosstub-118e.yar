rule TTP_XOR_MULT_DOSStub_118e {
  strings:
    $key_118e = { 45 e6 [2] 31 fe [2] 76 fc [2] 31 ed [2] 7f e1 [2] 73 eb [2] 64 e0 [2] 7f ae [2] 42 }

  condition:
    any of them
}