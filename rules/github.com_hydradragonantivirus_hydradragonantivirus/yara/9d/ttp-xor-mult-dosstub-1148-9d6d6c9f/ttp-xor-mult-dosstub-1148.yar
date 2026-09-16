rule TTP_XOR_MULT_DOSStub_1148 {
  strings:
    $key_1148 = { 45 20 [2] 31 38 [2] 76 3a [2] 31 2b [2] 7f 27 [2] 73 2d [2] 64 26 [2] 7f 68 [2] 42 }

  condition:
    any of them
}