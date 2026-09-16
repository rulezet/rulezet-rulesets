rule TTP_XOR_MULT_DOSStub_230a {
  strings:
    $key_230a = { 77 62 [2] 03 7a [2] 44 78 [2] 03 69 [2] 4d 65 [2] 41 6f [2] 56 64 [2] 4d 2a [2] 70 }

  condition:
    any of them
}