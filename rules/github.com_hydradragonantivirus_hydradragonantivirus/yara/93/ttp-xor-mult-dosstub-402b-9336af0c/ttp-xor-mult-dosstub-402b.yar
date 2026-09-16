rule TTP_XOR_MULT_DOSStub_402b {
  strings:
    $key_402b = { 14 43 [2] 60 5b [2] 27 59 [2] 60 48 [2] 2e 44 [2] 22 4e [2] 35 45 [2] 2e 0b [2] 13 }

  condition:
    any of them
}