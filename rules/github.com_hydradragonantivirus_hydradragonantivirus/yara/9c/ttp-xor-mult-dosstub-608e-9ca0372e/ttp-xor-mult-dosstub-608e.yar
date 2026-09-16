rule TTP_XOR_MULT_DOSStub_608e {
  strings:
    $key_608e = { 34 e6 [2] 40 fe [2] 07 fc [2] 40 ed [2] 0e e1 [2] 02 eb [2] 15 e0 [2] 0e ae [2] 33 }

  condition:
    any of them
}