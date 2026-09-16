rule TTP_XOR_MULT_DOSStub_4f12 {
  strings:
    $key_4f12 = { 1b 7a [2] 6f 62 [2] 28 60 [2] 6f 71 [2] 21 7d [2] 2d 77 [2] 3a 7c [2] 21 32 [2] 1c }

  condition:
    any of them
}