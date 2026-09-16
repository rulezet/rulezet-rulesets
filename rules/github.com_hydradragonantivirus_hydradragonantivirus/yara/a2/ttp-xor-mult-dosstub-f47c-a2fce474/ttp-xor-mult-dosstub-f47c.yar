rule TTP_XOR_MULT_DOSStub_f47c {
  strings:
    $key_f47c = { a0 14 [2] d4 0c [2] 93 0e [2] d4 1f [2] 9a 13 [2] 96 19 [2] 81 12 [2] 9a 5c [2] a7 }

  condition:
    any of them
}