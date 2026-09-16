rule TTP_XOR_MULT_DOSStub_1109 {
  strings:
    $key_1109 = { 45 61 [2] 31 79 [2] 76 7b [2] 31 6a [2] 7f 66 [2] 73 6c [2] 64 67 [2] 7f 29 [2] 42 }

  condition:
    any of them
}