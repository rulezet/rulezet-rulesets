rule TTP_XOR_MULT_DOSStub_f78e {
  strings:
    $key_f78e = { a3 e6 [2] d7 fe [2] 90 fc [2] d7 ed [2] 99 e1 [2] 95 eb [2] 82 e0 [2] 99 ae [2] a4 }

  condition:
    any of them
}