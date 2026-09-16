rule TTP_XOR_MULT_DOSStub_6418 {
  strings:
    $key_6418 = { 30 70 [2] 44 68 [2] 03 6a [2] 44 7b [2] 0a 77 [2] 06 7d [2] 11 76 [2] 0a 38 [2] 37 }

  condition:
    any of them
}