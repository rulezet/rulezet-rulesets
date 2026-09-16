rule TTP_XOR_MULT_DOSStub_f034 {
  strings:
    $key_f034 = { a4 5c [2] d0 44 [2] 97 46 [2] d0 57 [2] 9e 5b [2] 92 51 [2] 85 5a [2] 9e 14 [2] a3 }

  condition:
    any of them
}