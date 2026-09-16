rule TTP_XOR_MULT_DOSStub_f109 {
  strings:
    $key_f109 = { a5 61 [2] d1 79 [2] 96 7b [2] d1 6a [2] 9f 66 [2] 93 6c [2] 84 67 [2] 9f 29 [2] a2 }

  condition:
    any of them
}