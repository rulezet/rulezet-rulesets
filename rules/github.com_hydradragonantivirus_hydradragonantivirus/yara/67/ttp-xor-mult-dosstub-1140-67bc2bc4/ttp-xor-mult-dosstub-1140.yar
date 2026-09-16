rule TTP_XOR_MULT_DOSStub_1140 {
  strings:
    $key_1140 = { 45 28 [2] 31 30 [2] 76 32 [2] 31 23 [2] 7f 2f [2] 73 25 [2] 64 2e [2] 7f 60 [2] 42 }

  condition:
    any of them
}