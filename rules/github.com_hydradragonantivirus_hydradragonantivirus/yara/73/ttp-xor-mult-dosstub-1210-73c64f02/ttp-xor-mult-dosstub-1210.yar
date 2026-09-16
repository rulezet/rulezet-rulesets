rule TTP_XOR_MULT_DOSStub_1210 {
  strings:
    $key_1210 = { 46 78 [2] 32 60 [2] 75 62 [2] 32 73 [2] 7c 7f [2] 70 75 [2] 67 7e [2] 7c 30 [2] 41 }

  condition:
    any of them
}