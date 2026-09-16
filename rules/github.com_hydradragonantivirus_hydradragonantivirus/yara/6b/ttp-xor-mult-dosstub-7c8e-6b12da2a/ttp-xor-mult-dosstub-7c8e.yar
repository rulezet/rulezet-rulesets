rule TTP_XOR_MULT_DOSStub_7c8e {
  strings:
    $key_7c8e = { 28 e6 [2] 5c fe [2] 1b fc [2] 5c ed [2] 12 e1 [2] 1e eb [2] 09 e0 [2] 12 ae [2] 2f }

  condition:
    any of them
}