rule TTP_XOR_MULT_DOSStub_037c {
  strings:
    $key_037c = { 57 14 [2] 23 0c [2] 64 0e [2] 23 1f [2] 6d 13 [2] 61 19 [2] 76 12 [2] 6d 5c [2] 50 }

  condition:
    any of them
}