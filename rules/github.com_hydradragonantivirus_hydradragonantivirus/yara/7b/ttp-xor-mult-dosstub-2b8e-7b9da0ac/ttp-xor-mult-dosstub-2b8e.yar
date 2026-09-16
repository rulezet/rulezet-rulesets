rule TTP_XOR_MULT_DOSStub_2b8e {
  strings:
    $key_2b8e = { 7f e6 [2] 0b fe [2] 4c fc [2] 0b ed [2] 45 e1 [2] 49 eb [2] 5e e0 [2] 45 ae [2] 78 }

  condition:
    any of them
}