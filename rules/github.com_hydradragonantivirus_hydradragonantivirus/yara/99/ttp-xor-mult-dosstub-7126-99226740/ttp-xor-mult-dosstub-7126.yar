rule TTP_XOR_MULT_DOSStub_7126 {
  strings:
    $key_7126 = { 25 4e [2] 51 56 [2] 16 54 [2] 51 45 [2] 1f 49 [2] 13 43 [2] 04 48 [2] 1f 06 [2] 22 }

  condition:
    any of them
}