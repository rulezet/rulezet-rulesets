rule TTP_XOR_MULT_DOSStub_445b {
  strings:
    $key_445b = { 10 33 [2] 64 2b [2] 23 29 [2] 64 38 [2] 2a 34 [2] 26 3e [2] 31 35 [2] 2a 7b [2] 17 }

  condition:
    any of them
}