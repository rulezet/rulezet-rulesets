rule TTP_XOR_MULT_DOSStub_f118 {
  strings:
    $key_f118 = { a5 70 [2] d1 68 [2] 96 6a [2] d1 7b [2] 9f 77 [2] 93 7d [2] 84 76 [2] 9f 38 [2] a2 }

  condition:
    any of them
}