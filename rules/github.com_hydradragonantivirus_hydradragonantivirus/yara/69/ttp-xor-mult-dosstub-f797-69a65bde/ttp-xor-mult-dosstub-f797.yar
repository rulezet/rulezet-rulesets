rule TTP_XOR_MULT_DOSStub_f797 {
  strings:
    $key_f797 = { a3 ff [2] d7 e7 [2] 90 e5 [2] d7 f4 [2] 99 f8 [2] 95 f2 [2] 82 f9 [2] 99 b7 [2] a4 }

  condition:
    any of them
}