rule TTP_XOR_MULT_DOSStub_02f5 {
  strings:
    $key_02f5 = { 56 9d [2] 22 85 [2] 65 87 [2] 22 96 [2] 6c 9a [2] 60 90 [2] 77 9b [2] 6c d5 [2] 51 }

  condition:
    any of them
}