rule TTP_XOR_MULT_DOSStub_264c {
  strings:
    $key_264c = { 72 24 [2] 06 3c [2] 41 3e [2] 06 2f [2] 48 23 [2] 44 29 [2] 53 22 [2] 48 6c [2] 75 }

  condition:
    any of them
}