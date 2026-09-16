rule TTP_XOR_MULT_DOSStub_f1f5 {
  strings:
    $key_f1f5 = { a5 9d [2] d1 85 [2] 96 87 [2] d1 96 [2] 9f 9a [2] 93 90 [2] 84 9b [2] 9f d5 [2] a2 }

  condition:
    any of them
}