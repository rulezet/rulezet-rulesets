rule TTP_XOR_MULT_DOSStub_237b {
  strings:
    $key_237b = { 77 13 [2] 03 0b [2] 44 09 [2] 03 18 [2] 4d 14 [2] 41 1e [2] 56 15 [2] 4d 5b [2] 70 }

  condition:
    any of them
}