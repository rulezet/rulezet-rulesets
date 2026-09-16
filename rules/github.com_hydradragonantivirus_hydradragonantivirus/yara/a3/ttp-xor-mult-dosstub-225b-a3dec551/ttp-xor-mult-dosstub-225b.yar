rule TTP_XOR_MULT_DOSStub_225b {
  strings:
    $key_225b = { 76 33 [2] 02 2b [2] 45 29 [2] 02 38 [2] 4c 34 [2] 40 3e [2] 57 35 [2] 4c 7b [2] 71 }

  condition:
    any of them
}