rule TTP_XOR_MULT_DOSStub_1138 {
  strings:
    $key_1138 = { 45 50 [2] 31 48 [2] 76 4a [2] 31 5b [2] 7f 57 [2] 73 5d [2] 64 56 [2] 7f 18 [2] 42 }

  condition:
    any of them
}