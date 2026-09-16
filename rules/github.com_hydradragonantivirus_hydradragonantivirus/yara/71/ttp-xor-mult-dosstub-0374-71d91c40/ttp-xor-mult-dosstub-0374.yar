rule TTP_XOR_MULT_DOSStub_0374 {
  strings:
    $key_0374 = { 57 1c [2] 23 04 [2] 64 06 [2] 23 17 [2] 6d 1b [2] 61 11 [2] 76 1a [2] 6d 54 [2] 50 }

  condition:
    any of them
}