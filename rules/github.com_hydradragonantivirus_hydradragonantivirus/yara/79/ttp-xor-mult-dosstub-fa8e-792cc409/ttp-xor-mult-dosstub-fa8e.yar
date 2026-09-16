rule TTP_XOR_MULT_DOSStub_fa8e {
  strings:
    $key_fa8e = { ae e6 [2] da fe [2] 9d fc [2] da ed [2] 94 e1 [2] 98 eb [2] 8f e0 [2] 94 ae [2] a9 }

  condition:
    any of them
}