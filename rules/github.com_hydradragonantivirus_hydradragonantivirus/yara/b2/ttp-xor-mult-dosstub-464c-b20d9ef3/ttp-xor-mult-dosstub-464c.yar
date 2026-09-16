rule TTP_XOR_MULT_DOSStub_464c {
  strings:
    $key_464c = { 12 24 [2] 66 3c [2] 21 3e [2] 66 2f [2] 28 23 [2] 24 29 [2] 33 22 [2] 28 6c [2] 15 }

  condition:
    any of them
}