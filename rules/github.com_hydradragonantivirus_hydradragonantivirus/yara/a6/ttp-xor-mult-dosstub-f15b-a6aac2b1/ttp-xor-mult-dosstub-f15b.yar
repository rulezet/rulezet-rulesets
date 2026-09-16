rule TTP_XOR_MULT_DOSStub_f15b {
  strings:
    $key_f15b = { a5 33 [2] d1 2b [2] 96 29 [2] d1 38 [2] 9f 34 [2] 93 3e [2] 84 35 [2] 9f 7b [2] a2 }

  condition:
    any of them
}