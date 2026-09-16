rule TTP_XOR_MULT_DOSStub_f065 {
  strings:
    $key_f065 = { a4 0d [2] d0 15 [2] 97 17 [2] d0 06 [2] 9e 0a [2] 92 00 [2] 85 0b [2] 9e 45 [2] a3 }

  condition:
    any of them
}