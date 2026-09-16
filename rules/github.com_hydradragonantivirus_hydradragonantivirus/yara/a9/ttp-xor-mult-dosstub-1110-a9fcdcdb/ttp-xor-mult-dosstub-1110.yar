rule TTP_XOR_MULT_DOSStub_1110 {
  strings:
    $key_1110 = { 45 78 [2] 31 60 [2] 76 62 [2] 31 73 [2] 7f 7f [2] 73 75 [2] 64 7e [2] 7f 30 [2] 42 }

  condition:
    any of them
}