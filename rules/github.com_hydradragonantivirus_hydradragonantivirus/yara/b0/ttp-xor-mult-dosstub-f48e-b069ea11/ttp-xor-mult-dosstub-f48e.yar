rule TTP_XOR_MULT_DOSStub_f48e {
  strings:
    $key_f48e = { a0 e6 [2] d4 fe [2] 93 fc [2] d4 ed [2] 9a e1 [2] 96 eb [2] 81 e0 [2] 9a ae [2] a7 }

  condition:
    any of them
}