rule TTP_XOR_MULT_DOSStub_032b {
  strings:
    $key_032b = { 57 43 [2] 23 5b [2] 64 59 [2] 23 48 [2] 6d 44 [2] 61 4e [2] 76 45 [2] 6d 0b [2] 50 }

  condition:
    any of them
}