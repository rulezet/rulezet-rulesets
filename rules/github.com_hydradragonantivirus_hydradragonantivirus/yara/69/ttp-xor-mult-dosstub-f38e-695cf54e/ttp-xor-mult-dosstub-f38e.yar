rule TTP_XOR_MULT_DOSStub_f38e {
  strings:
    $key_f38e = { a7 e6 [2] d3 fe [2] 94 fc [2] d3 ed [2] 9d e1 [2] 91 eb [2] 86 e0 [2] 9d ae [2] a0 }

  condition:
    any of them
}