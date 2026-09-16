rule TTP_XOR_MULT_DOSStub_f024 {
  strings:
    $key_f024 = { a4 4c [2] d0 54 [2] 97 56 [2] d0 47 [2] 9e 4b [2] 92 41 [2] 85 4a [2] 9e 04 [2] a3 }

  condition:
    any of them
}