rule TTP_XOR_MULT_DOSStub_f159 {
  strings:
    $key_f159 = { a5 31 [2] d1 29 [2] 96 2b [2] d1 3a [2] 9f 36 [2] 93 3c [2] 84 37 [2] 9f 79 [2] a2 }

  condition:
    any of them
}