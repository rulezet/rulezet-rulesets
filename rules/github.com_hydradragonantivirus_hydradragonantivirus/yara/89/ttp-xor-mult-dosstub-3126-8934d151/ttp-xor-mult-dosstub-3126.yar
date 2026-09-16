rule TTP_XOR_MULT_DOSStub_3126 {
  strings:
    $key_3126 = { 65 4e [2] 11 56 [2] 56 54 [2] 11 45 [2] 5f 49 [2] 53 43 [2] 44 48 [2] 5f 06 [2] 62 }

  condition:
    any of them
}