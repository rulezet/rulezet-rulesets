rule TTP_XOR_MULT_DOSStub_308e {
  strings:
    $key_308e = { 64 e6 [2] 10 fe [2] 57 fc [2] 10 ed [2] 5e e1 [2] 52 eb [2] 45 e0 [2] 5e ae [2] 63 }

  condition:
    any of them
}