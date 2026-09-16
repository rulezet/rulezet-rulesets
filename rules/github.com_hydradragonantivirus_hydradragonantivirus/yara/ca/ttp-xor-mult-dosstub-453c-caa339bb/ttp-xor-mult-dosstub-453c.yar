rule TTP_XOR_MULT_DOSStub_453c {
  strings:
    $key_453c = { 11 54 [2] 65 4c [2] 22 4e [2] 65 5f [2] 2b 53 [2] 27 59 [2] 30 52 [2] 2b 1c [2] 16 }

  condition:
    any of them
}