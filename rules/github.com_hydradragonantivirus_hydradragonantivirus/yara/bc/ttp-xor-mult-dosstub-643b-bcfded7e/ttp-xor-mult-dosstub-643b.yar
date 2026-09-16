rule TTP_XOR_MULT_DOSStub_643b {
  strings:
    $key_643b = { 30 53 [2] 44 4b [2] 03 49 [2] 44 58 [2] 0a 54 [2] 06 5e [2] 11 55 [2] 0a 1b [2] 37 }

  condition:
    any of them
}