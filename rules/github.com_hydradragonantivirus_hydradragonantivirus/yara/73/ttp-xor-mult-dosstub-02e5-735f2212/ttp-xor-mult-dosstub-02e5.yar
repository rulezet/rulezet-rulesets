rule TTP_XOR_MULT_DOSStub_02e5 {
  strings:
    $key_02e5 = { 56 8d [2] 22 95 [2] 65 97 [2] 22 86 [2] 6c 8a [2] 60 80 [2] 77 8b [2] 6c c5 [2] 51 }

  condition:
    any of them
}