rule TTP_XOR_MULT_DOSStub_f104 {
  strings:
    $key_f104 = { a5 6c [2] d1 74 [2] 96 76 [2] d1 67 [2] 9f 6b [2] 93 61 [2] 84 6a [2] 9f 24 [2] a2 }

  condition:
    any of them
}