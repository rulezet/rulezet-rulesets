rule TTP_XOR_MULT_DOSStub_764c {
  strings:
    $key_764c = { 22 24 [2] 56 3c [2] 11 3e [2] 56 2f [2] 18 23 [2] 14 29 [2] 03 22 [2] 18 6c [2] 25 }

  condition:
    any of them
}