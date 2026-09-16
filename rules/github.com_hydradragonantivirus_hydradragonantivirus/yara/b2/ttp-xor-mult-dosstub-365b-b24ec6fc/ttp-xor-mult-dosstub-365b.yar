rule TTP_XOR_MULT_DOSStub_365b {
  strings:
    $key_365b = { 62 33 [2] 16 2b [2] 51 29 [2] 16 38 [2] 58 34 [2] 54 3e [2] 43 35 [2] 58 7b [2] 65 }

  condition:
    any of them
}