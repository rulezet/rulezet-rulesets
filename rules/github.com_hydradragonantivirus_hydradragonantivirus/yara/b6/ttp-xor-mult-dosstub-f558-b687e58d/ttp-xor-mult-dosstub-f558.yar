rule TTP_XOR_MULT_DOSStub_f558 {
  strings:
    $key_f558 = { a1 30 [2] d5 28 [2] 92 2a [2] d5 3b [2] 9b 37 [2] 97 3d [2] 80 36 [2] 9b 78 [2] a6 }

  condition:
    any of them
}