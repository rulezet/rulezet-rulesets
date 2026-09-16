rule TTP_XOR_MULT_DOSStub_1119 {
  strings:
    $key_1119 = { 45 71 [2] 31 69 [2] 76 6b [2] 31 7a [2] 7f 76 [2] 73 7c [2] 64 77 [2] 7f 39 [2] 42 }

  condition:
    any of them
}