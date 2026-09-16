rule TTP_XOR_MULT_DOSStub_f429 {
  strings:
    $key_f429 = { a0 41 [2] d4 59 [2] 93 5b [2] d4 4a [2] 9a 46 [2] 96 4c [2] 81 47 [2] 9a 09 [2] a7 }

  condition:
    any of them
}