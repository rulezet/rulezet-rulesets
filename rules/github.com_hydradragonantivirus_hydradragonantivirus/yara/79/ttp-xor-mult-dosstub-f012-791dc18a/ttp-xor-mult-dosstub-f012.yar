rule TTP_XOR_MULT_DOSStub_f012 {
  strings:
    $key_f012 = { a4 7a [2] d0 62 [2] 97 60 [2] d0 71 [2] 9e 7d [2] 92 77 [2] 85 7c [2] 9e 32 [2] a3 }

  condition:
    any of them
}