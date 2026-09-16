rule TTP_XOR_MULT_DOSStub_237c {
  strings:
    $key_237c = { 77 14 [2] 03 0c [2] 44 0e [2] 03 1f [2] 4d 13 [2] 41 19 [2] 56 12 [2] 4d 5c [2] 70 }

  condition:
    any of them
}