rule TTP_XOR_MULT_DOSStub_3131 {
  strings:
    $key_3131 = { 65 59 [2] 11 41 [2] 56 43 [2] 11 52 [2] 5f 5e [2] 53 54 [2] 44 5f [2] 5f 11 [2] 62 }

  condition:
    any of them
}