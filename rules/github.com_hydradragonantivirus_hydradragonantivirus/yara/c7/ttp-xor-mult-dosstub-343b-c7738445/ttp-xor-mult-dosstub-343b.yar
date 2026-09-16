rule TTP_XOR_MULT_DOSStub_343b {
  strings:
    $key_343b = { 60 53 [2] 14 4b [2] 53 49 [2] 14 58 [2] 5a 54 [2] 56 5e [2] 41 55 [2] 5a 1b [2] 67 }

  condition:
    any of them
}