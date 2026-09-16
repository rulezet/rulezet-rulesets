rule TTP_XOR_MULT_DOSStub_f68e {
  strings:
    $key_f68e = { a2 e6 [2] d6 fe [2] 91 fc [2] d6 ed [2] 98 e1 [2] 94 eb [2] 83 e0 [2] 98 ae [2] a5 }

  condition:
    any of them
}