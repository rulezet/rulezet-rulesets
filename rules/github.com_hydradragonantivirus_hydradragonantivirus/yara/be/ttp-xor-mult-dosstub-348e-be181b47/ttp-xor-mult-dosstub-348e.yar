rule TTP_XOR_MULT_DOSStub_348e {
  strings:
    $key_348e = { 60 e6 [2] 14 fe [2] 53 fc [2] 14 ed [2] 5a e1 [2] 56 eb [2] 41 e0 [2] 5a ae [2] 67 }

  condition:
    any of them
}