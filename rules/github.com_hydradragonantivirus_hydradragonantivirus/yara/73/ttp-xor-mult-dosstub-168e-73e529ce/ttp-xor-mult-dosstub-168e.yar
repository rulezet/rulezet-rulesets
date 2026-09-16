rule TTP_XOR_MULT_DOSStub_168e {
  strings:
    $key_168e = { 42 e6 [2] 36 fe [2] 71 fc [2] 36 ed [2] 78 e1 [2] 74 eb [2] 63 e0 [2] 78 ae [2] 45 }

  condition:
    any of them
}