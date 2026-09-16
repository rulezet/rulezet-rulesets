rule TTP_XOR_MULT_DOSStub_703d {
  strings:
    $key_703d = { 24 55 [2] 50 4d [2] 17 4f [2] 50 5e [2] 1e 52 [2] 12 58 [2] 05 53 [2] 1e 1d [2] 23 }

  condition:
    any of them
}