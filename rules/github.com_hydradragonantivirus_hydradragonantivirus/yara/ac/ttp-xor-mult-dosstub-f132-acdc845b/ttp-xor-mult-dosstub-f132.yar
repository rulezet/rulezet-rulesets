rule TTP_XOR_MULT_DOSStub_f132 {
  strings:
    $key_f132 = { a5 5a [2] d1 42 [2] 96 40 [2] d1 51 [2] 9f 5d [2] 93 57 [2] 84 5c [2] 9f 12 [2] a2 }

  condition:
    any of them
}