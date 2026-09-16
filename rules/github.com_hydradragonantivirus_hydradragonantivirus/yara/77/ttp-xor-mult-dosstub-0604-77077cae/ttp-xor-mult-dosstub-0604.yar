rule TTP_XOR_MULT_DOSStub_0604 {
  strings:
    $key_0604 = { 52 6c [2] 26 74 [2] 61 76 [2] 26 67 [2] 68 6b [2] 64 61 [2] 73 6a [2] 68 24 [2] 55 }

  condition:
    any of them
}