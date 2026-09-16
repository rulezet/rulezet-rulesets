rule TTP_XOR_MULT_DOSStub_518e {
  strings:
    $key_518e = { 05 e6 [2] 71 fe [2] 36 fc [2] 71 ed [2] 3f e1 [2] 33 eb [2] 24 e0 [2] 3f ae [2] 02 }

  condition:
    any of them
}