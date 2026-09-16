rule TTP_XOR_MULT_DOSStub_f008 {
  strings:
    $key_f008 = { a4 60 [2] d0 78 [2] 97 7a [2] d0 6b [2] 9e 67 [2] 92 6d [2] 85 66 [2] 9e 28 [2] a3 }

  condition:
    any of them
}