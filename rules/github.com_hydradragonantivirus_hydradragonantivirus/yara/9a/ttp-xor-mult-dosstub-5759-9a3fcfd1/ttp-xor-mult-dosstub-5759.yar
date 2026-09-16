rule TTP_XOR_MULT_DOSStub_5759 {
  strings:
    $key_5759 = { 03 31 [2] 77 29 [2] 30 2b [2] 77 3a [2] 39 36 [2] 35 3c [2] 22 37 [2] 39 79 [2] 04 }

  condition:
    any of them
}