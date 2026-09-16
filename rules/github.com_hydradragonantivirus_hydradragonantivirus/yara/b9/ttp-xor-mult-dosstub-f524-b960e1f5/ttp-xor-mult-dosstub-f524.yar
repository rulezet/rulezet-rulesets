rule TTP_XOR_MULT_DOSStub_f524 {
  strings:
    $key_f524 = { a1 4c [2] d5 54 [2] 92 56 [2] d5 47 [2] 9b 4b [2] 97 41 [2] 80 4a [2] 9b 04 [2] a6 }

  condition:
    any of them
}