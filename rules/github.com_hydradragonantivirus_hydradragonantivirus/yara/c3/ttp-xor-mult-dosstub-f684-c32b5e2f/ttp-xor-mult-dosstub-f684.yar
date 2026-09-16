rule TTP_XOR_MULT_DOSStub_f684 {
  strings:
    $key_f684 = { a2 ec [2] d6 f4 [2] 91 f6 [2] d6 e7 [2] 98 eb [2] 94 e1 [2] 83 ea [2] 98 a4 [2] a5 }

  condition:
    any of them
}