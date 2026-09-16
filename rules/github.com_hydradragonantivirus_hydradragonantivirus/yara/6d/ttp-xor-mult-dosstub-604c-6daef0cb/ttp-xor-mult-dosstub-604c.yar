rule TTP_XOR_MULT_DOSStub_604c {
  strings:
    $key_604c = { 34 24 [2] 40 3c [2] 07 3e [2] 40 2f [2] 0e 23 [2] 02 29 [2] 15 22 [2] 0e 6c [2] 33 }

  condition:
    any of them
}