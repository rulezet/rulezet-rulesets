rule TTP_XOR_MULT_DOSStub_702d {
  strings:
    $key_702d = { 24 45 [2] 50 5d [2] 17 5f [2] 50 4e [2] 1e 42 [2] 12 48 [2] 05 43 [2] 1e 0d [2] 23 }

  condition:
    any of them
}