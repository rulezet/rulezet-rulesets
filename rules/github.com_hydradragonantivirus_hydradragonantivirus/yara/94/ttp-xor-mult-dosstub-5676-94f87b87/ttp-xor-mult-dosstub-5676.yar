rule TTP_XOR_MULT_DOSStub_5676 {
  strings:
    $key_5676 = { 02 1e [2] 76 06 [2] 31 04 [2] 76 15 [2] 38 19 [2] 34 13 [2] 23 18 [2] 38 56 [2] 05 }

  condition:
    any of them
}