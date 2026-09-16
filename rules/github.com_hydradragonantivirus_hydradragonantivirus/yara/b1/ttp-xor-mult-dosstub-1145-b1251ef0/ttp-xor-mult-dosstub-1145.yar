rule TTP_XOR_MULT_DOSStub_1145 {
  strings:
    $key_1145 = { 45 2d [2] 31 35 [2] 76 37 [2] 31 26 [2] 7f 2a [2] 73 20 [2] 64 2b [2] 7f 65 [2] 42 }

  condition:
    any of them
}