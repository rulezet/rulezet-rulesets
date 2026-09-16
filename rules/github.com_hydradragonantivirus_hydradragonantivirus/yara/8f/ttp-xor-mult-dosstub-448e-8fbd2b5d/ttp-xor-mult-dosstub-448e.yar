rule TTP_XOR_MULT_DOSStub_448e {
  strings:
    $key_448e = { 10 e6 [2] 64 fe [2] 23 fc [2] 64 ed [2] 2a e1 [2] 26 eb [2] 31 e0 [2] 2a ae [2] 17 }

  condition:
    any of them
}