rule TTP_XOR_MULT_DOSStub_f019 {
  strings:
    $key_f019 = { a4 71 [2] d0 69 [2] 97 6b [2] d0 7a [2] 9e 76 [2] 92 7c [2] 85 77 [2] 9e 39 [2] a3 }

  condition:
    any of them
}