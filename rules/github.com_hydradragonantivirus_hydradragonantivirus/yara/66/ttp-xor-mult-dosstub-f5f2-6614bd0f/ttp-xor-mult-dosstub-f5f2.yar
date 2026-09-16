rule TTP_XOR_MULT_DOSStub_f5f2 {
  strings:
    $key_f5f2 = { a1 9a [2] d5 82 [2] 92 80 [2] d5 91 [2] 9b 9d [2] 97 97 [2] 80 9c [2] 9b d2 [2] a6 }

  condition:
    any of them
}