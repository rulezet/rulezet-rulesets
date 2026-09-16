rule TTP_XOR_MULT_DOSStub_1104 {
  strings:
    $key_1104 = { 45 6c [2] 31 74 [2] 76 76 [2] 31 67 [2] 7f 6b [2] 73 61 [2] 64 6a [2] 7f 24 [2] 42 }

  condition:
    any of them
}