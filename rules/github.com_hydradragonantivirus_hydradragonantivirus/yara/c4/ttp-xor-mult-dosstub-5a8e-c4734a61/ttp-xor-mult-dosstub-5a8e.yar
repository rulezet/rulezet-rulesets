rule TTP_XOR_MULT_DOSStub_5a8e {
  strings:
    $key_5a8e = { 0e e6 [2] 7a fe [2] 3d fc [2] 7a ed [2] 34 e1 [2] 38 eb [2] 2f e0 [2] 34 ae [2] 09 }

  condition:
    any of them
}