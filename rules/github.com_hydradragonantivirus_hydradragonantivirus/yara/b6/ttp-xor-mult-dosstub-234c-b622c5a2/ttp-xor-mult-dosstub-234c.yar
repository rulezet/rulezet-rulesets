rule TTP_XOR_MULT_DOSStub_234c {
  strings:
    $key_234c = { 77 24 [2] 03 3c [2] 44 3e [2] 03 2f [2] 4d 23 [2] 41 29 [2] 56 22 [2] 4d 6c [2] 70 }

  condition:
    any of them
}