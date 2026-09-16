rule TTP_XOR_MULT_DOSStub_1144 {
  strings:
    $key_1144 = { 45 2c [2] 31 34 [2] 76 36 [2] 31 27 [2] 7f 2b [2] 73 21 [2] 64 2a [2] 7f 64 [2] 42 }

  condition:
    any of them
}