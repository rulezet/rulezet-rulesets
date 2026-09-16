rule TTP_XOR_MULT_DOSStub_f1e1 {
  strings:
    $key_f1e1 = { a5 89 [2] d1 91 [2] 96 93 [2] d1 82 [2] 9f 8e [2] 93 84 [2] 84 8f [2] 9f c1 [2] a2 }

  condition:
    any of them
}