rule TTP_XOR_MULT_DOSStub_4c8e {
  strings:
    $key_4c8e = { 18 e6 [2] 6c fe [2] 2b fc [2] 6c ed [2] 22 e1 [2] 2e eb [2] 39 e0 [2] 22 ae [2] 1f }

  condition:
    any of them
}