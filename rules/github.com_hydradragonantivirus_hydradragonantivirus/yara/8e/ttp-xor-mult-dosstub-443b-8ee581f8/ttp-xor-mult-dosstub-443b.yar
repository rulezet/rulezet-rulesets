rule TTP_XOR_MULT_DOSStub_443b {
  strings:
    $key_443b = { 10 53 [2] 64 4b [2] 23 49 [2] 64 58 [2] 2a 54 [2] 26 5e [2] 31 55 [2] 2a 1b [2] 17 }

  condition:
    any of them
}