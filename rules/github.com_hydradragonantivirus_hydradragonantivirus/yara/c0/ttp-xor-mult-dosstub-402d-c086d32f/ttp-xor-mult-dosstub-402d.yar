rule TTP_XOR_MULT_DOSStub_402d {
  strings:
    $key_402d = { 14 45 [2] 60 5d [2] 27 5f [2] 60 4e [2] 2e 42 [2] 22 48 [2] 35 43 [2] 2e 0d [2] 13 }

  condition:
    any of them
}