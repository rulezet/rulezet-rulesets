rule TTP_XOR_MULT_DOSStub_1170 {
  strings:
    $key_1170 = { 45 18 [2] 31 00 [2] 76 02 [2] 31 13 [2] 7f 1f [2] 73 15 [2] 64 1e [2] 7f 50 [2] 42 }

  condition:
    any of them
}