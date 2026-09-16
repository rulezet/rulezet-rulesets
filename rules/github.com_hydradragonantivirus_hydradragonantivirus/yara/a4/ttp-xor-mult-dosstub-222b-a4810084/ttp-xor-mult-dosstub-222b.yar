rule TTP_XOR_MULT_DOSStub_222b {
  strings:
    $key_222b = { 76 43 [2] 02 5b [2] 45 59 [2] 02 48 [2] 4c 44 [2] 40 4e [2] 57 45 [2] 4c 0b [2] 71 }

  condition:
    any of them
}