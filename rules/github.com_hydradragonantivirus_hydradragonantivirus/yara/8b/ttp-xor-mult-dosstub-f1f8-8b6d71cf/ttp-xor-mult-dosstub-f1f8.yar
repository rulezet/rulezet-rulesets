rule TTP_XOR_MULT_DOSStub_f1f8 {
  strings:
    $key_f1f8 = { a5 90 [2] d1 88 [2] 96 8a [2] d1 9b [2] 9f 97 [2] 93 9d [2] 84 96 [2] 9f d8 [2] a2 }

  condition:
    any of them
}