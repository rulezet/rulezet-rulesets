rule TTP_XOR_MULT_DOSStub_037d {
  strings:
    $key_037d = { 57 15 [2] 23 0d [2] 64 0f [2] 23 1e [2] 6d 12 [2] 61 18 [2] 76 13 [2] 6d 5d [2] 50 }

  condition:
    any of them
}