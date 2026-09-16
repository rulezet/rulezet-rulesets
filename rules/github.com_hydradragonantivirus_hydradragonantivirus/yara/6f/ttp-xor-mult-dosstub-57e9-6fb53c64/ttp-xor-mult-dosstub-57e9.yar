rule TTP_XOR_MULT_DOSStub_57e9 {
  strings:
    $key_57e9 = { 03 81 [2] 77 99 [2] 30 9b [2] 77 8a [2] 39 86 [2] 35 8c [2] 22 87 [2] 39 c9 [2] 04 }

  condition:
    any of them
}