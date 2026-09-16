rule TTP_XOR_MULT_DOSStub_261b {
  strings:
    $key_261b = { 72 73 [2] 06 6b [2] 41 69 [2] 06 78 [2] 48 74 [2] 44 7e [2] 53 75 [2] 48 3b [2] 75 }

  condition:
    any of them
}