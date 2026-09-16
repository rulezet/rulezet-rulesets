rule TTP_XOR_MULT_DOSStub_0279 {
  strings:
    $key_0279 = { 56 11 [2] 22 09 [2] 65 0b [2] 22 1a [2] 6c 16 [2] 60 1c [2] 77 17 [2] 6c 59 [2] 51 }

  condition:
    any of them
}