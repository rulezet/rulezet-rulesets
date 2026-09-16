rule TTP_XOR_MULT_DOSStub_668e {
  strings:
    $key_668e = { 32 e6 [2] 46 fe [2] 01 fc [2] 46 ed [2] 08 e1 [2] 04 eb [2] 13 e0 [2] 08 ae [2] 35 }

  condition:
    any of them
}