rule TTP_XOR_MULT_DOSStub_57e8 {
  strings:
    $key_57e8 = { 03 80 [2] 77 98 [2] 30 9a [2] 77 8b [2] 39 87 [2] 35 8d [2] 22 86 [2] 39 c8 [2] 04 }

  condition:
    any of them
}