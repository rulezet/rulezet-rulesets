rule TTP_XOR_MULT_DOSStub_0263 {
  strings:
    $key_0263 = { 56 0b [2] 22 13 [2] 65 11 [2] 22 00 [2] 6c 0c [2] 60 06 [2] 77 0d [2] 6c 43 [2] 51 }

  condition:
    any of them
}