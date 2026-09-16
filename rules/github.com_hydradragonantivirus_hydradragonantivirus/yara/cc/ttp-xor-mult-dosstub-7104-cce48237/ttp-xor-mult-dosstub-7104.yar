rule TTP_XOR_MULT_DOSStub_7104 {
  strings:
    $key_7104 = { 25 6c [2] 51 74 [2] 16 76 [2] 51 67 [2] 1f 6b [2] 13 61 [2] 04 6a [2] 1f 24 [2] 22 }

  condition:
    any of them
}