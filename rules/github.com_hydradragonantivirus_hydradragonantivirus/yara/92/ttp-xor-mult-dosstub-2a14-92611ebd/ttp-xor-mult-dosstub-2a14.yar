rule TTP_XOR_MULT_DOSStub_2a14 {
  strings:
    $key_2a14 = { 7e 7c [2] 0a 64 [2] 4d 66 [2] 0a 77 [2] 44 7b [2] 48 71 [2] 5f 7a [2] 44 34 [2] 79 }

  condition:
    any of them
}