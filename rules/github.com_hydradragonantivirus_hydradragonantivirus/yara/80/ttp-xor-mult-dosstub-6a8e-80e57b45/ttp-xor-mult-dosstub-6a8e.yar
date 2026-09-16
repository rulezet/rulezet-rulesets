rule TTP_XOR_MULT_DOSStub_6a8e {
  strings:
    $key_6a8e = { 3e e6 [2] 4a fe [2] 0d fc [2] 4a ed [2] 04 e1 [2] 08 eb [2] 1f e0 [2] 04 ae [2] 39 }

  condition:
    any of them
}