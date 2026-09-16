rule TTP_XOR_MULT_DOSStub_3120 {
  strings:
    $key_3120 = { 65 48 [2] 11 50 [2] 56 52 [2] 11 43 [2] 5f 4f [2] 53 45 [2] 44 4e [2] 5f 00 [2] 62 }

  condition:
    any of them
}