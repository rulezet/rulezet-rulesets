rule TTP_XOR_MULT_DOSStub_454c {
  strings:
    $key_454c = { 11 24 [2] 65 3c [2] 22 3e [2] 65 2f [2] 2b 23 [2] 27 29 [2] 30 22 [2] 2b 6c [2] 16 }

  condition:
    any of them
}