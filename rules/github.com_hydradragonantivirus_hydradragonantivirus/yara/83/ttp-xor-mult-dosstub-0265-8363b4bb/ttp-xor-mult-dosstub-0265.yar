rule TTP_XOR_MULT_DOSStub_0265 {
  strings:
    $key_0265 = { 56 0d [2] 22 15 [2] 65 17 [2] 22 06 [2] 6c 0a [2] 60 00 [2] 77 0b [2] 6c 45 [2] 51 }

  condition:
    any of them
}