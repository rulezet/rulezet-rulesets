rule TTP_XOR_MULT_DOSStub_703b {
  strings:
    $key_703b = { 24 53 [2] 50 4b [2] 17 49 [2] 50 58 [2] 1e 54 [2] 12 5e [2] 05 55 [2] 1e 1b [2] 23 }

  condition:
    any of them
}