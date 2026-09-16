rule TTP_XOR_MULT_DOSStub_2e4c {
  strings:
    $key_2e4c = { 7a 24 [2] 0e 3c [2] 49 3e [2] 0e 2f [2] 40 23 [2] 4c 29 [2] 5b 22 [2] 40 6c [2] 7d }

  condition:
    any of them
}