rule TTP_XOR_MULT_DOSStub_f6e1 {
  strings:
    $key_f6e1 = { a2 89 [2] d6 91 [2] 91 93 [2] d6 82 [2] 98 8e [2] 94 84 [2] 83 8f [2] 98 c1 [2] a5 }

  condition:
    any of them
}