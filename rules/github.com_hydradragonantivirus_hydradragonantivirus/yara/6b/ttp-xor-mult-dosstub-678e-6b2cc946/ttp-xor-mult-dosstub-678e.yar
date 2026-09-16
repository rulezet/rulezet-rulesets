rule TTP_XOR_MULT_DOSStub_678e {
  strings:
    $key_678e = { 33 e6 [2] 47 fe [2] 00 fc [2] 47 ed [2] 09 e1 [2] 05 eb [2] 12 e0 [2] 09 ae [2] 34 }

  condition:
    any of them
}