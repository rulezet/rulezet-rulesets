rule TTP_XOR_MULT_DOSStub_1071 {
  strings:
    $key_1071 = { 44 19 [2] 30 01 [2] 77 03 [2] 30 12 [2] 7e 1e [2] 72 14 [2] 65 1f [2] 7e 51 [2] 43 }

  condition:
    any of them
}