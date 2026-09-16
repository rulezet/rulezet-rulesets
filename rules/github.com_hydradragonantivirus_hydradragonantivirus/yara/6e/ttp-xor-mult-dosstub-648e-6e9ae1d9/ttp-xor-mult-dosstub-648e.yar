rule TTP_XOR_MULT_DOSStub_648e {
  strings:
    $key_648e = { 30 e6 [2] 44 fe [2] 03 fc [2] 44 ed [2] 0a e1 [2] 06 eb [2] 11 e0 [2] 0a ae [2] 37 }

  condition:
    any of them
}