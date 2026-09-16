rule TTP_XOR_MULT_DOSStub_4f14 {
  strings:
    $key_4f14 = { 1b 7c [2] 6f 64 [2] 28 66 [2] 6f 77 [2] 21 7b [2] 2d 71 [2] 3a 7a [2] 21 34 [2] 1c }

  condition:
    any of them
}