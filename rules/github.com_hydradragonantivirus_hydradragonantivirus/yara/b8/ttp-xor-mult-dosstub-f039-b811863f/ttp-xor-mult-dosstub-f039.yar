rule TTP_XOR_MULT_DOSStub_f039 {
  strings:
    $key_f039 = { a4 51 [2] d0 49 [2] 97 4b [2] d0 5a [2] 9e 56 [2] 92 5c [2] 85 57 [2] 9e 19 [2] a3 }

  condition:
    any of them
}