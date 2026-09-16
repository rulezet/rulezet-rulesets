rule TTP_XOR_MULT_DOSStub_451b {
  strings:
    $key_451b = { 11 73 [2] 65 6b [2] 22 69 [2] 65 78 [2] 2b 74 [2] 27 7e [2] 30 75 [2] 2b 3b [2] 16 }

  condition:
    any of them
}