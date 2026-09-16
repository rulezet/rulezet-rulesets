rule TTP_XOR_MULT_DOSStub_105b {
  strings:
    $key_105b = { 44 33 [2] 30 2b [2] 77 29 [2] 30 38 [2] 7e 34 [2] 72 3e [2] 65 35 [2] 7e 7b [2] 43 }

  condition:
    any of them
}