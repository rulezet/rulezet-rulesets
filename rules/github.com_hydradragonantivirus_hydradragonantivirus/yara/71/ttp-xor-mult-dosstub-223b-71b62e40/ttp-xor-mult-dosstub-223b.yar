rule TTP_XOR_MULT_DOSStub_223b {
  strings:
    $key_223b = { 76 53 [2] 02 4b [2] 45 49 [2] 02 58 [2] 4c 54 [2] 40 5e [2] 57 55 [2] 4c 1b [2] 71 }

  condition:
    any of them
}