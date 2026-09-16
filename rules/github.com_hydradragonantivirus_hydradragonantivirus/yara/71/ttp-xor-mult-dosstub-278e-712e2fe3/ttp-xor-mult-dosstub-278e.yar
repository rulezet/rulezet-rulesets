rule TTP_XOR_MULT_DOSStub_278e {
  strings:
    $key_278e = { 73 e6 [2] 07 fe [2] 40 fc [2] 07 ed [2] 49 e1 [2] 45 eb [2] 52 e0 [2] 49 ae [2] 74 }

  condition:
    any of them
}