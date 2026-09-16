rule TTP_XOR_MULT_DOSStub_702c {
  strings:
    $key_702c = { 24 44 [2] 50 5c [2] 17 5e [2] 50 4f [2] 1e 43 [2] 12 49 [2] 05 42 [2] 1e 0c [2] 23 }

  condition:
    any of them
}