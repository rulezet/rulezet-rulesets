rule TTP_XOR_MULT_DOSStub_f09c {
  strings:
    $key_f09c = { a4 f4 [2] d0 ec [2] 97 ee [2] d0 ff [2] 9e f3 [2] 92 f9 [2] 85 f2 [2] 9e bc [2] a3 }

  condition:
    any of them
}