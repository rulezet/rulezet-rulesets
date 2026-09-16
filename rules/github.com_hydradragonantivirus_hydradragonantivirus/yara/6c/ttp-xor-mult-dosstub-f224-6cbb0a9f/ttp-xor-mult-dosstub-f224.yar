rule TTP_XOR_MULT_DOSStub_f224 {
  strings:
    $key_f224 = { a6 4c [2] d2 54 [2] 95 56 [2] d2 47 [2] 9c 4b [2] 90 41 [2] 87 4a [2] 9c 04 [2] a1 }

  condition:
    any of them
}