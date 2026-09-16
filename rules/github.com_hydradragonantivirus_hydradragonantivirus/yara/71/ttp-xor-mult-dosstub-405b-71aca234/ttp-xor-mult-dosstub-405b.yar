rule TTP_XOR_MULT_DOSStub_405b {
  strings:
    $key_405b = { 14 33 [2] 60 2b [2] 27 29 [2] 60 38 [2] 2e 34 [2] 22 3e [2] 35 35 [2] 2e 7b [2] 13 }

  condition:
    any of them
}