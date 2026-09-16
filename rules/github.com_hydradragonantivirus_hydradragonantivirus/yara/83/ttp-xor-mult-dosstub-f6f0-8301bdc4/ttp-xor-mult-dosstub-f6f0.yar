rule TTP_XOR_MULT_DOSStub_f6f0 {
  strings:
    $key_f6f0 = { a2 98 [2] d6 80 [2] 91 82 [2] d6 93 [2] 98 9f [2] 94 95 [2] 83 9e [2] 98 d0 [2] a5 }

  condition:
    any of them
}