rule TTP_XOR_MULT_DOSStub_5f14 {
  strings:
    $key_5f14 = { 0b 7c [2] 7f 64 [2] 38 66 [2] 7f 77 [2] 31 7b [2] 3d 71 [2] 2a 7a [2] 31 34 [2] 0c }

  condition:
    any of them
}