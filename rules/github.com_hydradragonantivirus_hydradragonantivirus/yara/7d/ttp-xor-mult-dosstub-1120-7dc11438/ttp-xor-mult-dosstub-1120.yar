rule TTP_XOR_MULT_DOSStub_1120 {
  strings:
    $key_1120 = { 45 48 [2] 31 50 [2] 76 52 [2] 31 43 [2] 7f 4f [2] 73 45 [2] 64 4e [2] 7f 00 [2] 42 }

  condition:
    any of them
}