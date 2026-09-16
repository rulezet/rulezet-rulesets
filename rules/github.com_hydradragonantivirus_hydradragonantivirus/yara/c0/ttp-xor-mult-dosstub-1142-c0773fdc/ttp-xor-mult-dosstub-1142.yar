rule TTP_XOR_MULT_DOSStub_1142 {
  strings:
    $key_1142 = { 45 2a [2] 31 32 [2] 76 30 [2] 31 21 [2] 7f 2d [2] 73 27 [2] 64 2c [2] 7f 62 [2] 42 }

  condition:
    any of them
}