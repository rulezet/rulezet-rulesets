rule TTP_XOR_MULT_DOSStub_57f5 {
  strings:
    $key_57f5 = { 03 9d [2] 77 85 [2] 30 87 [2] 77 96 [2] 39 9a [2] 35 90 [2] 22 9b [2] 39 d5 [2] 04 }

  condition:
    any of them
}