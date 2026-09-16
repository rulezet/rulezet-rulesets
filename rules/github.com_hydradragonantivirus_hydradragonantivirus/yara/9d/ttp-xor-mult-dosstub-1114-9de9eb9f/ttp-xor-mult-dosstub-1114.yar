rule TTP_XOR_MULT_DOSStub_1114 {
  strings:
    $key_1114 = { 45 7c [2] 31 64 [2] 76 66 [2] 31 77 [2] 7f 7b [2] 73 71 [2] 64 7a [2] 7f 34 [2] 42 }

  condition:
    any of them
}