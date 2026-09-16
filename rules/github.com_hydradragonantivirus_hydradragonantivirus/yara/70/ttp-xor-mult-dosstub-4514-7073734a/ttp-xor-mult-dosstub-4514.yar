rule TTP_XOR_MULT_DOSStub_4514 {
  strings:
    $key_4514 = { 11 7c [2] 65 64 [2] 22 66 [2] 65 77 [2] 2b 7b [2] 27 71 [2] 30 7a [2] 2b 34 [2] 16 }

  condition:
    any of them
}