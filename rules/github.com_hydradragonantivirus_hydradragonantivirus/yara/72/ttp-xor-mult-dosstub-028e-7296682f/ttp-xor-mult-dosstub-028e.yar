rule TTP_XOR_MULT_DOSStub_028e {
  strings:
    $key_028e = { 56 e6 [2] 22 fe [2] 65 fc [2] 22 ed [2] 6c e1 [2] 60 eb [2] 77 e0 [2] 6c ae [2] 51 }

  condition:
    any of them
}