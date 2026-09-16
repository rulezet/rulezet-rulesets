rule TTP_XOR_MULT_DOSStub_761b {
  strings:
    $key_761b = { 22 73 [2] 56 6b [2] 11 69 [2] 56 78 [2] 18 74 [2] 14 7e [2] 03 75 [2] 18 3b [2] 25 }

  condition:
    any of them
}