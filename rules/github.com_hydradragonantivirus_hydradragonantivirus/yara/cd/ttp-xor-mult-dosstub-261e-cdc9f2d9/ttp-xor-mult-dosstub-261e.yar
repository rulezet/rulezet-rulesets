rule TTP_XOR_MULT_DOSStub_261e {
  strings:
    $key_261e = { 72 76 [2] 06 6e [2] 41 6c [2] 06 7d [2] 48 71 [2] 44 7b [2] 53 70 [2] 48 3e [2] 75 }

  condition:
    any of them
}