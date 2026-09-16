rule TTP_XOR_MULT_DOSStub_1102 {
  strings:
    $key_1102 = { 45 6a [2] 31 72 [2] 76 70 [2] 31 61 [2] 7f 6d [2] 73 67 [2] 64 6c [2] 7f 22 [2] 42 }

  condition:
    any of them
}