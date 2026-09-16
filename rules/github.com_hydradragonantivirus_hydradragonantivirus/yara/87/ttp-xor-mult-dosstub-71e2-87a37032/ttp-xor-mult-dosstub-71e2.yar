rule TTP_XOR_MULT_DOSStub_71e2 {
  strings:
    $key_71e2 = { 25 8a [2] 51 92 [2] 16 90 [2] 51 81 [2] 1f 8d [2] 13 87 [2] 04 8c [2] 1f c2 [2] 22 }

  condition:
    any of them
}