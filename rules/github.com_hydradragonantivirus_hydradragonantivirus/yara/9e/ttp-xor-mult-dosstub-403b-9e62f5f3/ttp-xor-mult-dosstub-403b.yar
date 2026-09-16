rule TTP_XOR_MULT_DOSStub_403b {
  strings:
    $key_403b = { 14 53 [2] 60 4b [2] 27 49 [2] 60 58 [2] 2e 54 [2] 22 5e [2] 35 55 [2] 2e 1b [2] 13 }

  condition:
    any of them
}