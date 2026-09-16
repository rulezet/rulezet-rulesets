rule TTP_XOR_MULT_DOSStub_5f19 {
  strings:
    $key_5f19 = { 0b 71 [2] 7f 69 [2] 38 6b [2] 7f 7a [2] 31 76 [2] 3d 7c [2] 2a 77 [2] 31 39 [2] 0c }

  condition:
    any of them
}